#!/usr/bin/env python3
"""Write an EFI_SIGNATURE_LIST holding one X.509 certificate.

The list format (UEFI 2.10 §32.4.1): EFI_CERT_X509_GUID, SignatureListSize,
SignatureHeaderSize (0), SignatureSize, then one EFI_SIGNATURE_DATA of
SignatureOwner GUID + the DER certificate. This is what U-Boot's variable
preseed expects as the PK/KEK/db payload. It mirrors pkg/uefi/esl.go in the
platform repository; it lives here so the builder container works without a
Go toolchain.
"""
import argparse
import struct
import sys
import uuid

EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")


def der_from_file(path: str) -> bytes:
    data = open(path, "rb").read()
    if b"-----BEGIN" in data:
        from OpenSSL import crypto  # pyOpenSSL, present for tools/efivar.py

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        return crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True, help="X.509 certificate, PEM or DER")
    ap.add_argument("--owner", required=True, help="SignatureOwner GUID")
    ap.add_argument("--out", required=True, help="output .esl path")
    args = ap.parse_args()

    der = der_from_file(args.cert)
    owner = uuid.UUID(args.owner)
    sig_size = 16 + len(der)
    list_size = 28 + sig_size
    with open(args.out, "wb") as f:
        f.write(EFI_CERT_X509_GUID.bytes_le)
        f.write(struct.pack("<III", list_size, 0, sig_size))
        f.write(owner.bytes_le)
        f.write(der)
    return 0


if __name__ == "__main__":
    sys.exit(main())
