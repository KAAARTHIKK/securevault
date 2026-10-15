"""Generate a self-signed TLS certificate for the local demo (doc 06 Phase 4).

The ABE secret key travels from the Key Authority to the client over this
connection, so the demo must not run on plain HTTP. For a real deployment use a
CA-issued certificate behind a reverse proxy instead.

    python scripts/gen_self_signed_cert.py
    uvicorn backend.app.main:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt

Then sign in to the client with the API base URL https://localhost:8443/api/v1
and the "Verify TLS certificate" box unchecked (self-signed only).
"""
import argparse
import datetime
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).resolve().parents[1] / "certs"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate a self-signed cert for the demo")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--out", default=str(CERTS_DIR))
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "server.key"
    crt_path = out_dir / "server.crt"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVault (demo)"),
    ])
    alt_names = [x509.DNSName(args.host)]
    if args.host == "localhost":
        alt_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    print("Wrote %s and %s (valid %d days, CN=%s)" % (crt_path, key_path, args.days, args.host))
    print("certs/ is gitignored -- never commit a private key.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
