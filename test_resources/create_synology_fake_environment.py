#!/usr/bin/env python3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

TAILSCALE_DIRECTORY = Path("/var/packages/Tailscale/etc")
TAILSCALE_ACME_KEY = TAILSCALE_DIRECTORY.joinpath("certs/acme-account.key.pem")
TAILSCALE_SOCKET = TAILSCALE_DIRECTORY.joinpath("tailscaled.sock")

SYNO_SYSTEM_DIR = Path("/usr/syno/etc/certificate")
SYNO_PKG_DIR = Path("/usr/local/etc/certificate")
SYNO_ARCHIVE_DIR = SYNO_SYSTEM_DIR.joinpath("_archive")
SYNO_CERT_INFO_FILE = SYNO_ARCHIVE_DIR.joinpath("INFO")
SYNO_CERT_DEFAULT_FILE = SYNO_ARCHIVE_DIR.joinpath("DEFAULT")

ONE_DAY = timedelta(1, 0, 0)


def create_cert_and_key():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    cert = (
        x509.CertificateBuilder()
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "tailscale-cert-synology-updater"
                    ),
                ]
            )
        )
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "tailscale-cert-synology-updater"
                    ),
                ]
            )
        )
        .not_valid_before(datetime.utcnow() - (ONE_DAY * 120))
        .not_valid_after(datetime.utcnow() + (ONE_DAY * 786))
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

    return (
        cert.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )


def main():
    TAILSCALE_DIRECTORY.mkdir(parents=True)
    SYNO_ARCHIVE_DIR.mkdir(parents=True)
    SYNO_PKG_DIR.mkdir(parents=True)

    base_dir = Path(__file__).resolve().parent

    SYNO_CERT_DEFAULT_FILE.write_text("XSYQT3\n")

    loaded_info: Dict = json.loads(base_dir.joinpath("INFO_only_system").read_text())
    for id, konf in loaded_info.items():
        path = SYNO_ARCHIVE_DIR.joinpath(id)
        path.mkdir()
        cert, key = create_cert_and_key()
        path.joinpath("cert.pem").write_bytes(cert)
        path.joinpath("fullchain.pem").write_bytes(cert)
        path.joinpath("privkey.pem").write_bytes(key)
        for service in konf["services"]:
            is_pkg = service.get("isPkg")
            subscriber = service.get("subscriber")
            service_id = service.get("service")
            root_dir = SYNO_PKG_DIR if is_pkg else SYNO_SYSTEM_DIR
            service_path = root_dir.joinpath(subscriber).joinpath(service_id)
            service_path.mkdir(parents=True, exist_ok=True)
            service_path.joinpath("cert.pem").write_bytes(cert)
            service_path.joinpath("fullchain.pem").write_bytes(cert)
            service_path.joinpath("privkey.pem").write_bytes(key)

    Path("/usr/local/bin/synoservice").symlink_to("/bin/true")


if __name__ == "__main__":
    main()
