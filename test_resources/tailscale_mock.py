import socketserver
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ONE_DAY = timedelta(1, 0, 0)


class TailscaleMock:
    def __init__(self, socket_path: str):
        self.last_cert: Optional[x509.Certificate] = None
        self.socket_path = socket_path
        self.server = None
        self.requesthandler = None
        self.backdate = False

    def _create_cert(self) -> bytes:

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
                        x509.NameAttribute(NameOID.COMMON_NAME, "certiboi"),
                    ]
                )
            )
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "certiboi"),
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

    @classmethod
    def create(cls, socket_path):
        this = cls(socket_path)

        class UnixSocketHttpServer(socketserver.UnixStreamServer):
            def get_request(self):
                request, _ = super(UnixSocketHttpServer, self).get_request()
                return (request, ["local", 0])

        class HttpRequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                url = urlparse(self.path)

                if not url.path.startswith("/localapi/v0/cert/"):
                    raise Exception(f"Did not expect path: {self.path}")

                if not url.query == "type=cert":
                    raise Exception(f"Did not expect query: {url.query}")

                content = this._create_cert()

                self.send_response(200, "OK")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        this.requesthandler = HttpRequestHandler
        this.server = UnixSocketHttpServer
        return this

    def run(self):
        if self.server is None or self.requesthandler is None:
            raise Exception("Create instance with the create() method")

        with self.server((self.socket_path), self.requesthandler) as server:
            server.serve_forever()
