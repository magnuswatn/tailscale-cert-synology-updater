import socketserver
import sys
import traceback
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID
from josepy.jwa import ES256
from josepy.jwk import JWKEC

ONE_DAY = timedelta(1, 0, 0)
LETSENCRYPT_DIRECTORY = "https://pebble:14000/dir"

TAILSCALE_DIRECTORY = Path("/var/packages/Tailscale/etc")
TAILSCALE_ACME_KEY = TAILSCALE_DIRECTORY.joinpath("certs/acme-account.key.pem")


class TailscaleMock:
    def __init__(self, socket_path: str):
        self.last_cert: Optional[x509.Certificate] = None
        self.socket_path = socket_path
        self.server = None
        self.requesthandler = None
        self.backdate = False
        self.acme = False

    def _get_acme_cert(self, domain):
        private_key = ec.generate_private_key(curve=ec.SECP256R1)  # type: ignore

        TAILSCALE_ACME_KEY.parent.mkdir(parents=True, exist_ok=True)
        TAILSCALE_ACME_KEY.write_bytes(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )

        acme_key = JWKEC(key=private_key)
        network = client.ClientNetwork(acme_key, alg=ES256)

        directory = messages.Directory.from_json(
            network.get(LETSENCRYPT_DIRECTORY).json()
        )
        acme_client = client.ClientV2(directory, network)

        new_regr = messages.NewRegistration.from_data(
            email="dummyboi@watn.no", terms_of_service_agreed=True
        )
        acme_client.new_account(new_regr)
        acme_client = acme_client

        private_key = ec.generate_private_key(curve=ec.SECP256R1)  # type: ignore

        request = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, domain),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        ).public_bytes(Encoding.PEM)

        order = acme_client.new_order(request)

        for authz in order.authorizations:
            for challenge in authz.body.challenges:  # type: ignore
                if challenge.typ != "dns-01":
                    continue
                response, validation = challenge.response_and_validation(acme_key)
                acme_client.answer_challenge(challenge, response)

        order = acme_client.poll_and_finalize(
            order, datetime.now() + timedelta(seconds=90)
        )

        self.last_cert = x509.load_pem_x509_certificate(
            order.fullchain_pem.encode("ASCII")
        )

        return order.fullchain_pem.encode("ASCII")

    def _create_selfsigned_cert(self, domain) -> bytes:
        private_key = ec.generate_private_key(curve=ec.SECP256R1)  # type: ignore

        not_valid_before = (
            datetime.utcnow() - timedelta(365, 0, 0)
            if self.backdate
            else datetime.utcnow()
        )

        cert = (
            x509.CertificateBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, domain),
                    ]
                )
            )
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, domain),
                    ]
                )
            )
            .not_valid_before(not_valid_before)
            .not_valid_after(datetime.utcnow() + timedelta(7, 0, 0))
            .serial_number(x509.random_serial_number())
            .public_key(private_key.public_key())
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
            )
        )
        self.last_cert = cert

        return cert.public_bytes(serialization.Encoding.PEM)

    def _get_cert(self, domain: str):
        return (
            self._get_acme_cert(domain)
            if self.acme
            else self._create_selfsigned_cert(domain)
        )

    @classmethod
    def create(cls, socket_path):
        this = cls(socket_path)

        class UnixSocketHttpServer(socketserver.UnixStreamServer):
            def get_request(self):
                request, _ = super(UnixSocketHttpServer, self).get_request()
                return (request, ["local", 0])

        class HttpRequestHandler(BaseHTTPRequestHandler):
            CERT_URL = "/localapi/v0/cert/"
            INVALID_REQ_ERROR = b"invalid localapi request"

            def is_valid_request(self) -> bool:
                # https://github.com/tailscale/tailscale/blob/8e4a29433f48b192f30da3a164e6ac3b6674b0bc/ipn/localapi/localapi.go#L199
                if self.headers["origin"]:
                    return False

                if self.headers["referer"]:
                    return False

                host = self.headers["host"]
                if not host or host == "local-tailscaled.sock":
                    return True

                return False

            def return_resp(self, status: Tuple[int, str], content: bytes) -> None:
                self.send_response(*status)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def do_GET(self):
                if not self.is_valid_request():
                    self.return_resp((403, "Forbidden"), self.INVALID_REQ_ERROR)
                    return

                url = urlparse(self.path)

                if not url.path.startswith(self.CERT_URL):
                    raise Exception(f"Did not expect path: {self.path}")

                if not url.query == "type=cert":
                    raise Exception(f"Did not expect query: {url.query}")

                domain = url.path[len(self.CERT_URL) :]

                try:
                    content = this._get_cert(domain)
                    status = (200, "OK")
                except Exception:
                    content = "".join(
                        traceback.format_exception(*sys.exc_info())
                    ).encode()
                    status = (500, "Internal Server Error")

                self.return_resp(status, content)

        this.requesthandler = HttpRequestHandler
        this.server = UnixSocketHttpServer
        return this

    def run(self):
        if self.server is None or self.requesthandler is None:
            raise Exception("Create instance with the create() method")

        with self.server((self.socket_path), self.requesthandler) as server:
            server.serve_forever()
