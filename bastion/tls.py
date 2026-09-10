"""TLS cert generation and fingerprinting helpers for the master."""

import hashlib
import ssl
import subprocess
from pathlib import Path

from bastion.common import subprocess_env


def gen_cert(certs_dir, common_name):
    certs_dir = Path(certs_dir)
    certs_dir.mkdir(parents=True, exist_ok=True)
    certfile = certs_dir / "master.crt"
    keyfile = certs_dir / "master.key"

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", str(keyfile),
            "-out", str(certfile),
            "-days", "3650", "-nodes",
            "-subj", f"/CN={common_name}",
        ],
        check=True,
        env=subprocess_env(),
    )
    return certfile, keyfile


def fingerprint_of_file(certfile):
    pem = Path(certfile).read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()
