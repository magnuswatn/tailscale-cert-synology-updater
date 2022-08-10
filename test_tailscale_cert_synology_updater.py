import os
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

from tailscale_cert_synology_updater import (
    CertRetriever,
    CertWithKey,
    SynologyCertConfig,
    TailscaleCertSynologyUpdaterException,
    TailscaleClient,
    renew_cert_if_needed,
)
from test_resources.tailscale_mock import TailscaleMock, TAILSCALE_ACME_KEY

SYNO_CERT_INFO_FILE = Path("/usr/syno/etc/certificate/_archive/INFO")

PEBBLE_DIRECTORY = "https://pebble:14000/dir"
PEBBLE_MGMT_INTERFACE = "https://pebble:15000/"

INFO_MOCK_ONLY_SYSTEM = Path("./test_resources/INFO_only_system")
INFO_MOCK_NO_TAILSCALE = Path("./test_resources/INFO_no_tailscalecert")
INFO_MOCK_EXTRA_SERVICES = Path("./test_resources/INFO_with_extra_services")


@pytest.fixture(scope="session", autouse=True)
def tailscale_mock():
    with tempfile.TemporaryDirectory() as temp_dir:
        if os.environ.get("RUNNING_IN_DOCKER"):
            socket = "/var/packages/Tailscale/etc/tailscaled.sock"
        else:
            socket = f"{temp_dir}/tailscaled.socket"

        mock = TailscaleMock.create(socket)
        thread = threading.Thread(target=mock.run)
        thread.daemon = True
        thread.start()
        yield mock
        Path(socket).unlink()


def validate_cert_from_pebble(cert: x509.Certificate):
    resp = requests.get(
        f"{PEBBLE_MGMT_INTERFACE}/cert-status-by-serial/{format(cert.serial_number, 'x')}"
    )
    assert resp.status_code == 200
    json_resp: Dict[str, str] = resp.json()
    assert json_resp.get("Status") == "Valid"
    raw_cert_from_pebble: str = json_resp["Certificate"]
    cert_from_pebble = x509.load_pem_x509_certificate(
        raw_cert_from_pebble.encode("ASCII")
    )
    assert cert_from_pebble == cert


class DummyCertGenerator:
    def __init__(self):
        self.last_cert: Optional[x509.Certificate] = None

    def dummy_get_new_cert(self, domain) -> CertWithKey:

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
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
            .not_valid_before(datetime.utcnow() - timedelta(120, 0, 0))
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

        return CertWithKey(
            cert.public_bytes(serialization.Encoding.PEM).decode("ASCII"),
            private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ),
        )


@pytest.mark.skipif(
    os.environ.get("RUNNING_IN_DOCKER") == None, reason="only to be run in Docker"
)
class TestRenewCertIfNeeded:
    domain = "mynasbox.something-something.ts.net"

    def test_no_tailscale_cert_found(self):

        SYNO_CERT_INFO_FILE.write_bytes(INFO_MOCK_NO_TAILSCALE.read_bytes())

        with pytest.raises(Exception) as error:
            renew_cert_if_needed(
                self.domain,
                SynologyCertConfig.create(),
                TailscaleClient.create(),
                DummyCertGenerator().dummy_get_new_cert,
            )
        assert (
            "Could not locate a Tailscale certificate in the Synology configuration"
            in str(error.value)
        )

    def test_only_system(self, tailscale_mock: TailscaleMock):

        SYNO_CERT_INFO_FILE.write_bytes(INFO_MOCK_ONLY_SYSTEM.read_bytes())
        tailscale_mock.backdate = False
        tailscale_mock.acme = True

        renew_cert_if_needed(
            self.domain,
            SynologyCertConfig.create(),
            TailscaleClient.create(),
            CertRetriever(PEBBLE_DIRECTORY).get_new_cert,
        )
        syno_cert_config = SynologyCertConfig.create()
        tailscale_cert = syno_cert_config.get_tailscale_cert()
        assert tailscale_cert is not None
        validate_cert_from_pebble(tailscale_cert.get_x509_cert())

        assert (
            Path(f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/cert.pem")
            .read_text()
            .startswith("-----BEGIN CERTIFICATE-----")
        )
        assert (
            Path(f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/privkey.pem")
            .read_text()
            .startswith("-----BEGIN PRIVATE KEY-----")
        )

        # should have been updated
        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/cert.pem"
            ).read_bytes()
            == Path("/usr/syno/etc/certificate/system/default/cert.pem").read_bytes()
        )

        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/privkey.pem"
            ).read_bytes()
            == Path("/usr/syno/etc/certificate/system/default/privkey.pem").read_bytes()
        )

        # should not have been updated
        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/cert.pem"
            ).read_bytes()
            != Path(
                "/usr/local/etc/certificate/HyperBackupVault/HyperBackupVault/cert.pem"
            ).read_bytes()
        )

        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/privkey.pem"
            ).read_bytes()
            != Path(
                "/usr/local/etc/certificate/HyperBackupVault/HyperBackupVault/privkey.pem"
            ).read_bytes()
        )

    def test_extra_services(self, tailscale_mock: TailscaleMock):

        SYNO_CERT_INFO_FILE.write_bytes(INFO_MOCK_EXTRA_SERVICES.read_bytes())
        tailscale_mock.backdate = False
        tailscale_mock.acme = True

        renew_cert_if_needed(
            self.domain,
            SynologyCertConfig.create(),
            TailscaleClient.create(),
            CertRetriever(PEBBLE_DIRECTORY).get_new_cert,
        )
        syno_cert_config = SynologyCertConfig.create()
        tailscale_cert = syno_cert_config.get_tailscale_cert()
        assert tailscale_cert is not None
        validate_cert_from_pebble(tailscale_cert.get_x509_cert())

        # should have been updated
        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/cert.pem"
            ).read_bytes()
            == Path("/usr/syno/etc/certificate/system/default/cert.pem").read_bytes()
        )

        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/privkey.pem"
            ).read_bytes()
            == Path("/usr/syno/etc/certificate/system/default/privkey.pem").read_bytes()
        )

        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/cert.pem"
            ).read_bytes()
            == Path(
                "/usr/local/etc/certificate/HyperBackupVault/HyperBackupVault/cert.pem"
            ).read_bytes()
        )

        assert (
            Path(
                f"/usr/syno/etc/certificate/_archive/{tailscale_cert.id}/privkey.pem"
            ).read_bytes()
            == Path(
                "/usr/local/etc/certificate/HyperBackupVault/HyperBackupVault/privkey.pem"
            ).read_bytes()
        )

    def test_no_updated_needed(self, tailscale_mock: TailscaleMock):

        SYNO_CERT_INFO_FILE.write_bytes(INFO_MOCK_ONLY_SYSTEM.read_bytes())
        tailscale_mock.backdate = True
        tailscale_mock.acme = False

        pre_tailscale_cert = SynologyCertConfig.create().get_tailscale_cert()
        assert pre_tailscale_cert is not None

        dummy_cert_generator = DummyCertGenerator()

        renew_cert_if_needed(
            self.domain,
            SynologyCertConfig.create(),
            TailscaleClient.create(),
            dummy_cert_generator.dummy_get_new_cert,
        )
        syno_cert_config = SynologyCertConfig.create()
        tailscale_cert = syno_cert_config.get_tailscale_cert()

        assert tailscale_cert == pre_tailscale_cert
        assert dummy_cert_generator.last_cert is None


@pytest.mark.skipif(
    os.environ.get("RUNNING_IN_DOCKER") == None, reason="only to be run in Docker"
)
class TestCertRetriever:
    def test_invalid_authz(self, tailscale_mock: TailscaleMock):

        SYNO_CERT_INFO_FILE.write_bytes(INFO_MOCK_ONLY_SYSTEM.read_bytes())
        tailscale_mock.acme = True

        pre_tailscale_cert = SynologyCertConfig.create().get_tailscale_cert()
        assert pre_tailscale_cert is not None

        with pytest.raises(TailscaleCertSynologyUpdaterException) as error:
            CertRetriever(PEBBLE_DIRECTORY).get_new_cert("wrongy.mc.wrong.face")

        assert (
            "The Tailscale acme client did not have a valid authorization for this "
            + "domain. Delete the Tailscale cert and try again"
            in str(error)
        )

    def test_missing_account(self, tailscale_mock: TailscaleMock):
        dummy_file = TAILSCALE_ACME_KEY.parent.joinpath("moved")
        TAILSCALE_ACME_KEY.rename(dummy_file)

        with pytest.raises(TailscaleCertSynologyUpdaterException) as error:
            CertRetriever(PEBBLE_DIRECTORY).get_new_cert("wrongy.mc.wrong.face")

        assert "Did not find the Tailscale acme account key" in str(error)
        dummy_file.rename(TAILSCALE_ACME_KEY)


class TestTailscaleClient:
    def test_get_cert(self, tailscale_mock: TailscaleMock):
        tailscale_client = TailscaleClient.create(tailscale_mock.socket_path)
        tailscale_cert = tailscale_client.get_cert("hei")
        assert tailscale_cert == tailscale_mock.last_cert


class TestSynologyCertConfig:
    def test_get_tailscale_cert(self):
        syno_cert_config = SynologyCertConfig.create_from_text(
            INFO_MOCK_ONLY_SYSTEM.read_text()
        )
        tailscale_cert = syno_cert_config.get_tailscale_cert()
        assert tailscale_cert is not None
        assert tailscale_cert.id == "xyFnPF"
        assert len(tailscale_cert.services) == 1

    def test_get_tailscale_cert_none(self):
        syno_cert_config = SynologyCertConfig.create_from_text(
            INFO_MOCK_NO_TAILSCALE.read_text()
        )
        tailscale_cert = syno_cert_config.get_tailscale_cert()
        assert tailscale_cert is None
