import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union, cast

import httpx
from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID
from josepy.jwa import ES256
from josepy.jwk import JWK

CERT_DESC = "Managed by tailscale-cert-synology-updater"

LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"

TAILSCALE_DIRECTORY = Path("/var/packages/Tailscale/etc")
TAILSCALE_ACME_KEY = TAILSCALE_DIRECTORY.joinpath("certs/acme-account.key.pem")
TAILSCALE_SOCKET = TAILSCALE_DIRECTORY.joinpath("tailscaled.sock")

SYNO_SYSTEM_DIR = Path("/usr/syno/etc/certificate")
SYNO_PKG_DIR = Path("/usr/local/etc/certificate")
SYNO_ARCHIVE_DIR = SYNO_SYSTEM_DIR.joinpath("_archive")
SYNO_CERT_INFO_FILE = SYNO_ARCHIVE_DIR.joinpath("INFO")


class TailscaleCertSynologyUpdaterException(Exception):
    ...


@dataclass
class RequestWithKey:
    req: bytes
    key: bytes


@dataclass
class CertWithKey:
    cert: str
    key: bytes


@dataclass
class SynologyCert:
    id: str
    desc: str
    services: List[Dict[str, Union[str, bool]]]

    def get_x509_cert(self) -> x509.Certificate:
        raw_cert = SYNO_ARCHIVE_DIR.joinpath(self.id).joinpath("cert.pem").read_bytes()
        return x509.load_pem_x509_certificate(raw_cert)

    def install_cert_files(self, cert_with_key: CertWithKey):
        for path in self._get_paths():
            path.joinpath("cert.pem").write_text(cert_with_key.cert)
            path.joinpath("fullchain.pem").write_text(cert_with_key.cert)
            path.joinpath("privkey.pem").write_bytes(cert_with_key.key)

    def _get_paths(self):
        paths: List[Path] = [SYNO_ARCHIVE_DIR.joinpath(self.id)]
        for service in self.services:
            is_pkg = cast(bool, service.get("isPkg"))
            subscriber = cast(str, service.get("subscriber"))
            service_id = cast(str, service.get("service"))

            root_dir = SYNO_PKG_DIR if is_pkg else SYNO_SYSTEM_DIR
            paths.append(root_dir.joinpath(subscriber).joinpath(service_id))
        return paths


@dataclass
class SynologyCertConfig:
    certs: List[SynologyCert]

    @classmethod
    def create(cls):
        return cls.create_from_text(SYNO_CERT_INFO_FILE.read_text())

    @classmethod
    def create_from_text(cls, text: str):
        info = json.loads(text)
        certs: List[SynologyCert] = []

        id: str
        cert_info: Dict[str, Any]
        for id, cert_info in info.items():
            desc: str = cert_info.pop("desc")
            services = cert_info.pop("services")
            certs.append(SynologyCert(id, desc, services))
        return cls(certs)

    def get_tailscale_cert(self) -> Optional[SynologyCert]:

        for cert in self.certs:
            if cert.desc == CERT_DESC:
                return cert

        return None


class TailscaleClient:
    TAILSCALE_CERT_URL = "http://./localapi/v0/cert/{}"
    TIMEOUT = 600.0  # initial cert retrival can take a while

    def __init__(self, client: httpx.Client):
        self.client = client

    @classmethod
    def create(cls, socket_path=str(TAILSCALE_SOCKET)):
        client = httpx.Client(
            transport=httpx.HTTPTransport(uds=socket_path), timeout=cls.TIMEOUT
        )
        return cls(client)

    def get_cert(self, domain: str) -> x509.Certificate:
        url = self.TAILSCALE_CERT_URL.format(domain)
        response = self.client.get(url, params={"type": "cert"})
        response.raise_for_status()
        # We get the full chain from Tailscale here, but this
        # will only load the end entity cert, as we want.
        return x509.load_pem_x509_certificate(response.content)


class CertRetriever:
    def __init__(self, directory_url: str):
        self.directory_url = directory_url

    def _create_csr(self, domain: str) -> RequestWithKey:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
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
                x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
            )
            .sign(private_key, hashes.SHA256())
        )

        return RequestWithKey(
            req=request.public_bytes(Encoding.PEM),
            key=private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ),
        )

    def get_new_cert(self, domain: str) -> CertWithKey:
        if not TAILSCALE_ACME_KEY.exists():
            raise TailscaleCertSynologyUpdaterException(
                "Did not find the Tailscale acme account key"
            )

        jwk = JWK.load(TAILSCALE_ACME_KEY.read_bytes())
        network = client.ClientNetwork(jwk, alg=ES256)

        directory = messages.Directory.from_json(network.get(self.directory_url).json())
        acme_client = client.ClientV2(directory, network)

        # Tailscale only stores the account key, not the Key ID,
        # so we need to query the CA to update our registration.
        regr = acme_client.query_registration(
            messages.RegistrationResource(body=messages.Registration())
        )
        if regr.body.status != messages.STATUS_VALID.name:
            raise TailscaleCertSynologyUpdaterException(
                f"Tailscale acme account was not valid. Had status: {regr.body.status}"
            )

        req_with_key = self._create_csr(domain)

        order = acme_client.new_order(req_with_key.req)
        if order.body.status != messages.STATUS_READY:
            raise TailscaleCertSynologyUpdaterException(
                f"The Tailscale acme client did not have a valid "
                f"authorization for this domain. Delete the Tailscale cert and try again. "
                f"Order got status: {order.body.status}"
            )

        order = acme_client.finalize_order(
            order, datetime.now() + timedelta(seconds=90)
        )

        return CertWithKey(order.fullchain_pem, req_with_key.key)


def restart_services():
    # TODO: restart other services as well?
    subprocess.run(["synoservice", "--restart", "nginx"])


def renew_cert_if_needed(
    domain: str,
    syno_cert_config: SynologyCertConfig,
    tailscale_client: TailscaleClient,
    get_new_cert_func: Callable[[str], CertWithKey],
):
    syno_cert = syno_cert_config.get_tailscale_cert()
    try:
        tailscale_cert = tailscale_client.get_cert(domain)
    except httpx.HTTPStatusError as error:
        raise TailscaleCertSynologyUpdaterException(
            f"Got error from Tailscale ({error.response.status_code}): "
            f"{error.response.text}"
        ) from error

    if syno_cert is None:
        raise TailscaleCertSynologyUpdaterException(
            f"Could not locate a Tailscale certificate in the Synology configuration. "
            f"If this is the first run, add a dummy cert with the description '{CERT_DESC}'"
        )

    if tailscale_cert.not_valid_before <= syno_cert.get_x509_cert().not_valid_before:
        # The Tailscale cert has not been renewed after
        # our cert was issued, so no need to update.
        return

    new_cert_with_key = get_new_cert_func(domain)

    syno_cert.install_cert_files(new_cert_with_key)

    restart_services()


def main():
    if len(sys.argv) != 2:
        sys.exit("Wrong usage. Domain should be the only arg")
    domain = sys.argv[1]

    renew_cert_if_needed(
        domain,
        SynologyCertConfig.create(),
        TailscaleClient.create(),
        CertRetriever(LETSENCRYPT_DIRECTORY).get_new_cert,
    )


if __name__ == "__main__":
    main()
