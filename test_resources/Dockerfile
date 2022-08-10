# Python 3.8 is what's on the Synology atm.
FROM python:3.8-slim-bullseye

RUN set -x && python3 -m venv /opt/tailscale_cert_synology_updater/venv
ENV PATH="/opt/tailscale_cert_synology_updater/venv/bin:${PATH}"

COPY requirements-dev.txt /tmp/tailscale_cert_synology_updater/

RUN set -x && pip --no-cache-dir --disable-pip-version-check install --upgrade pip
RUN set -x && pip install -r /tmp/tailscale_cert_synology_updater/requirements-dev.txt

COPY test_resources/create_synology_fake_environment.py /tmp/tailscale_cert_synology_updater/
COPY test_resources/INFO_only_system /tmp/tailscale_cert_synology_updater/

RUN /tmp/tailscale_cert_synology_updater/create_synology_fake_environment.py
