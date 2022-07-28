# Run from the root of the repo (docker build -f test_resources/Dockerfile .)
FROM python:3.9-slim-bullseye

RUN set -x && python3 -m venv /opt/tailscale_cert_synology_updater/venv
ENV PATH="/opt/tailscale_cert_synology_updater/venv/bin:${PATH}"

COPY requirements-dev.txt /opt/tailscale_cert_synology_updater

RUN set -x && pip --no-cache-dir --disable-pip-version-check install --upgrade pip
RUN set -x && pip install -r /opt/tailscale_cert_synology_updater/requirements-dev.txt

COPY test_resources /opt/tailscale_cert_synology_updater/test_resources
RUN /opt/tailscale_cert_synology_updater/test_resources/create_synology_fake_environment.py

COPY tailscale_cert_synology_updater.py /opt/tailscale_cert_synology_updater
COPY test_tailscale_cert_synology_updater.py /opt/tailscale_cert_synology_updater

WORKDIR /opt/tailscale_cert_synology_updater

ENV RUNNING_IN_DOCKER=true
CMD python -um pytest
