tailscale-cert-synology-updater
===

This is a small application that updates the admin interface of your Synology NAS with the cert from Tailscale (kind of).

It is made for DSM 6, which does not support EC keys, which Tailscale [is hardcoded to generate](https://github.com/tailscale/tailscale/blob/9bd3b5b89c60534a9066902ae54b52f5797365bd/ipn/localapi/cert.go#L284), so it generates it's own RSA key and piggybacks on Tailscale's authorization to get it's own certificate. It then install this for the DSM web console.


## Limitations

It has only been tested on DSM 6, and even though it has support for using the cert for other purposes than the system cert, it is not very well tested. It will also, at the moment, just restart nginx after the cert has been installed, not other services. And, obviously, it is not supported by neither Synology nor Tailscale, so *use at your own risk*.

## Installation

Tailscale and Python 3 must be installed on the Synology from the Package Center. Tailscale must be joined to your tailnet and must be able to retrieve certificates (see [bug 4060](https://github.com/tailscale/tailscale/issues/4060) for details). Then manually install a "dummy cert" for the Synology using the GUI. Give it the description `Managed by tailscale-cert-synology-updater` and assign the system service to it. You can just use any certificate (e.g. a self-signed cert) for this, but if you have retrieved the certificate from Tailscale before, it *must* have a `not before` date before the Tailscale cert (or else it won't be replaced by the app).

This cert and key can be used for convenience:

```
-----BEGIN CERTIFICATE-----
MIIC8jCCAdqgAwIBAgIUIjaAiT913IQkS8kqoRpKjzTzs2AwDQYJKoZIhvcNAQEL
BQAwKjEoMCYGA1UEAwwfdGFpbHNjYWxlLWNlcnQtc3lub2xvZ3ktdXBkYXRlcjAe
Fw0yMTA3MjcxNDIwMTBaFw0yNDA5MjAxNDIwMTBaMCoxKDAmBgNVBAMMH3RhaWxz
Y2FsZS1jZXJ0LXN5bm9sb2d5LXVwZGF0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC6ldQKev7ZwAJAZjpi5Elt9tNquZbI/bMtZwrUHNc8/wt2sCUM
atZ7noph72YEgDZUEhu6UMDbvUXhIQe8LUzIBayTy3FJMmeIBPy0Quq4osNTvfKn
xO7rsbVXm4nCDOuM5tiV1YEh/qW9Yue75CkzyoM9HZ+mZhYea5ri3pi+ZRCq8iuO
rCCNx2Nxz2aOxT+cavrUyQ9+/xbxbmvvdXYjHhFgZVgh6tFcyhT9XPkaPTYUHaLj
eYTMteqlmGwd+xk6MJrrXaFtVd4yhJ8n6keAWK8gcGkTI0Qvyg9b98HpPztlMGkh
9JxlkgHuHEVUOGvKyWG0oteoT3hsKNSY9YyZAgMBAAGjEDAOMAwGA1UdEwEB/wQC
MAAwDQYJKoZIhvcNAQELBQADggEBAAWGw4EdwN5v0uUTMAx3RjdaE8KDXfgvdrGj
ZW/1PqTKYzhzAwg3QRp92Fl7ANJ+IdyZjaFCqa+XbtPSD+wyQisC8DPSTrrXnL/U
JdD07O6nfbjSr6OmmxUpwJCA4eBqmHFNIK0735ZeaHBWevKVPnoVU61GD/hoAuBT
DUuD5b6pj9dRrZlB0/g+EudfAJKeGy/kh6ys7CbctT2IX5v7H8Nvj8eza0v3W+Qr
W+oiWzj9PzrYY7zU/BrrsZ62jIEG379NoS+gO0aekB+z2nfMLaaf9Ad1xKqoiJeP
ssblJr6naCW6aNnlBtbnhER9AjeroB/mEvtGgxk6k+oPZkV8z/c=
-----END CERTIFICATE-----
```

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6ldQKev7ZwAJA
Zjpi5Elt9tNquZbI/bMtZwrUHNc8/wt2sCUMatZ7noph72YEgDZUEhu6UMDbvUXh
IQe8LUzIBayTy3FJMmeIBPy0Quq4osNTvfKnxO7rsbVXm4nCDOuM5tiV1YEh/qW9
Yue75CkzyoM9HZ+mZhYea5ri3pi+ZRCq8iuOrCCNx2Nxz2aOxT+cavrUyQ9+/xbx
bmvvdXYjHhFgZVgh6tFcyhT9XPkaPTYUHaLjeYTMteqlmGwd+xk6MJrrXaFtVd4y
hJ8n6keAWK8gcGkTI0Qvyg9b98HpPztlMGkh9JxlkgHuHEVUOGvKyWG0oteoT3hs
KNSY9YyZAgMBAAECggEAAwiq5Bk8IdsGBllLL362BXJXHXQDVEUQx+cWJV0LMGgW
vgEu9wjZMDUjm6ROgLn7eCo7tm+39RK6q0aT1z7W0eVKuTP8hXPK/GqVV9KDOcmW
urq60njIqD8xW0lxh9zZKyc5RBVuxjhbZk0Qhsz20QtkzyZ3STe9ehTmlbQIIIdh
zXCIAqCzfUNNG4z1Dm5lwT0tN7xxH0eAGMdlwKSf1OZZflYwZATeJArz1I4y/D2+
wGeiA4nzzVFxFH+BK5Cn/Azf8WNqdveyxbmBz/kUbtq1Kjffy95eelOb6Ora8H35
/QKoo0sBWp/70x/vkaGVQQfv5biVAaG7i2dEGRvQ0QKBgQDikafVQD7GkZXfMmIR
y+vDx6vE1GrNsnsQUNKAqSjViCejIJWZsp1oLfJMIqSzV3NQa78CvuDG7HepBgpH
u5fQ8WcWbWyuZk9VEZOGGyKCE45HYpKVRQyR5nnyiPvrPdI/7uVw5h8TF3wa3qNL
3TNCqkZJa+3SDGpiUOPJJ3isEQKBgQDS0o0auFHgZ7BNLfbmVw4rpmXqBKdxSDy0
uvnnPa4y31NtVWs2DTl+OZndVRy9pvx33U8etJC7aJucqBfgUja0+I115QF4gXnZ
xqLz4N+TtlQlJ4fCgoZxQYO0y9VJByfMpkY/3YH1nppncJW54HJYRpLJkbaeb9gx
Apngj7+ACQKBgGopPa7ab4+zX7o5bWJRXqNZx85uiazgWHGIrVnD6XJEXe49sltW
KhNKlCHAidPOwiWIlvO+ZKxQ2LDGN8Lsz3ID6v3DQA1nuvxtQ+auiDjS2PPx6CUx
OXaTu8g9D21mhkGWusNv0FetxWUBtRozB3XROyXkAIdPcfmnVVRHvm9BAoGBAITl
x599a9e7ZW7xt7+yRzOK/JnN/0OxFtuTNm/n+QUGtQ+qFiCHq6N/ahgVTD3doy9o
ajTf/JC3O8lASXTWPrhMKtiT2R5++DIpPpXgPvBdsqONTM53+4ovk3gIOlaD1Tnz
4zrlRsRwC8ODPE9lRo+RRX0dhvJPbQhQLHJcC4sJAoGBAK8orziDpllLl7A9cVfO
dDF1IC6S/umnnseNUAVO2IhAmOY5Cfb5ur29MVIJmcPniUQVdr34fB19fZxuDr8X
Cr+gvgjsys+wo01L+qryS5mSSJlZadh5+uh4jM/z4HsShpXWZ3+alYfu6CO/CHL/
o0qEKh6KRXLncQ3CX8WR67RK
-----END PRIVATE KEY-----
```

Then SSH into the NAS and install the app. It can be done either through the install script, which will install it to `/volume1/@tailscale-cert-synology-updater/`:

```
sudo mkdir "/volume1/@tailscale-cert-synology-updater/"
sudo chown "$USER:" "/volume1/@tailscale-cert-synology-updater/"
curl "https://raw.githubusercontent.com/magnuswatn/tailscale-cert-synology-updater/main/install.sh" | bash
```

or manually:

```
cd MY_FOLDER
curl "https://raw.githubusercontent.com/magnuswatn/tailscale-cert-synology-updater/main/requirements.txt" -o requirements.txt
curl "https://raw.githubusercontent.com/magnuswatn/tailscale-cert-synology-updater/main/tailscale_cert_synology_updater.py" -o tailscale_cert_synology_updater.py
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
```

Then install a nightly scheduled task via the Synology Control Panel, running the command: `/volume1/@tailscale-cert-synology-updater/venv/bin/python /volume1/@tailscale-cert-synology-updater/tailscale_cert_synology_updater.py mynas.something-something.ts.net` (update the path and your Tailscale domain name). It must run as root.

Run the task manually. This should replace your dummycert with a working Let's Encrypt cert for your Tailscale domain!

The app will check if the certs need updating every time it is run, and if Tailscale gives us a new cert ([14 days prior to expiry](https://github.com/tailscale/tailscale/blob/9bd3b5b89c60534a9066902ae54b52f5797365bd/ipn/localapi/cert.go#L106)) then it will retrieve a new cert and update it. It will restart nginx after the cert has been replaced.


## Troubleshooting

If it fails with `Got error from Tailscale`: make sure that you are running as root. Try to retrieve the cert with the `tailscale cert` command, and if that doesn't work, check the `/var/packages/Tailscale/etc/tailscaled.stdout.log` log, to see what went wrong.

If it fails with `The Tailscale acme client did not have a valid authorization for this domain`: The authorization to retrieve new certs [lasts 30 days](https://letsencrypt.org/docs/faq/#i-successfully-renewed-a-certificate-but-validation-didn-t-happen-this-time-how-is-that-possible), so if the Tailscale cert was generated over 30 days ago, the authorization has expired. This app is dependant on a valid authorization from Tailscale to retrieve a cert, as it cannot do the DNS challenge. Delete the cached cert and key from `/var/packages/Tailscale/etc/certs` so that Tailscale will retrieve a new cert and try again.


## Developing

To test with a "Synology like" filesystem, use the Docker container. Build it with `docker build -f test_resources/Dockerfile .`. When run it will run the test cases.
