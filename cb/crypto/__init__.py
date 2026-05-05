"""cb crypto - cryptographic primitive detection in binaries.

Identifies AES, SHA family, MD5, DES, ChaCha20, RC4, RSA, ECC, CRC and other
cryptographic algorithms in compiled binaries by their constants, S-boxes,
and structural patterns. Detects misuse (static IVs, hardcoded keys, ECB,
weak/deprecated algorithms) and rolled crypto (modified S-boxes).
"""
from cb.crypto.scanner import scan_binary, scan_bytes
from cb.crypto.constants import CRYPTO_FINGERPRINTS, build_fingerprints

__all__ = ["scan_binary", "scan_bytes", "CRYPTO_FINGERPRINTS",
           "build_fingerprints"]
