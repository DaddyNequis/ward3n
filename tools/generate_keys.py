#!/usr/bin/env python3
"""
generate_keys.py — Generate a P-256 key pair + self-signed X.509 cert
for the ward3n PIV firmware prototype.

Usage:
    python3 tools/generate_keys.py

Output:
    • Prints the DER cert and private key as C arrays you can embed directly.
    • Saves private_key.pem and cert.pem for inspection.

Dependencies:
    pip install cryptography

The firmware normally generates its own key pair on first boot and stores it
in flash. Use this script when you want to:
  • Inspect or export the key pair for debugging.
  • Pre-provision a known key pair (e.g., during manufacturing).
  • Generate a cert with specific extensions for macOS trust.
"""

import datetime
import ipaddress
import sys
import os

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: 'cryptography' package not found.")
    print("Install it with:  pip install cryptography")
    sys.exit(1)


def generate():
    # ── Key pair ──────────────────────────────────────────────────────────────
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key  = private_key.public_key()

    # ── Self-signed X.509 certificate ────────────────────────────────────────
    now = datetime.datetime.utcnow().replace(microsecond=0)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,            "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "ward3n"),
        x509.NameAttribute(NameOID.COMMON_NAME,             "ward3n PIV Key"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * 25))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,   # 1.3.6.1.5.5.7.3.2 — macOS smart card login
                ExtendedKeyUsageOID.SMARTCARD_LOGON,  # 1.3.6.1.4.1.311.20.2.2
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # ── Export DER ────────────────────────────────────────────────────────────
    cert_der    = cert.public_bytes(serialization.Encoding.DER)
    privkey_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    # Raw P-256 private scalar (big-endian, 32 bytes)
    priv_nums  = private_key.private_numbers()
    raw_priv   = priv_nums.private_value.to_bytes(32, "big")
    pub_nums   = public_key.public_key() if hasattr(public_key, "public_key") else public_key
    ec_pub     = private_key.public_key().public_numbers()
    raw_pub_x  = ec_pub.x.to_bytes(32, "big")
    raw_pub_y  = ec_pub.y.to_bytes(32, "big")

    # ── Save PEM files ────────────────────────────────────────────────────────
    script_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(script_dir, "private_key.pem"), "wb") as f:
        f.write(privkey_pem)
    with open(os.path.join(script_dir, "cert.pem"), "wb") as f:
        f.write(cert_pem)
    print("Wrote: tools/private_key.pem")
    print("Wrote: tools/cert.pem")

    # ── Print C arrays ────────────────────────────────────────────────────────
    def c_array(name, data):
        hex_bytes = ", ".join(f"0x{b:02X}" for b in data)
        lines = []
        raw = list(data)
        rows = [raw[i:i+16] for i in range(0, len(raw), 16)]
        body = ",\n    ".join(", ".join(f"0x{b:02X}" for b in row) for row in rows)
        return (
            f"static const uint8_t {name}[{len(data)}] = {{\n"
            f"    {body}\n"
            f"}};\n"
        )

    print("\n" + "=" * 72)
    print("/* Copy the following into include/crypto_keys.h */")
    print("=" * 72 + "\n")

    print(f"/* Certificate length */")
    print(f"#define CERT_9A_LEN {len(cert_der)}u\n")
    print(c_array("PRIVATE_KEY_9A_RAW", raw_priv))
    print(c_array("PUBLIC_KEY_9A_X",    raw_pub_x))
    print(c_array("PUBLIC_KEY_9A_Y",    raw_pub_y))
    print(c_array("CERT_9A_DER",        cert_der))

    print("=" * 72)
    print(f"\nCertificate fingerprint (SHA-256):")
    fp = cert.fingerprint(hashes.SHA256())
    print("  " + ":".join(f"{b:02X}" for b in fp))
    print(f"\nCertificate subject:  {cert.subject.rfc4514_string()}")
    print(f"Valid from:           {cert.not_valid_before}")
    print(f"Valid until:          {cert.not_valid_after}")
    print(f"Private key (raw, hex):\n  {raw_priv.hex()}")


if __name__ == "__main__":
    generate()
