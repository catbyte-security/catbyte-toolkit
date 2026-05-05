"""Cryptographic primitive fingerprints.

Each fingerprint is a (mostly) immutable byte sequence that identifies a
specific algorithm. We compute most constants from first principles
(AES S-box, SHA round constants, CRC tables) rather than transcribing
literal bytes — that way the database is provably correct.

Each fingerprint entry has:
    name:      algorithm + role (e.g. "AES S-box")
    algorithm: short id used for risk scoring (aes, sha256, md5, ...)
    bytes:     the byte pattern to search for
    endian:    "be", "le", or "any" (for byte-symmetric data like S-boxes)
    severity:  "ok" | "warn" | "critical" | "info"
    confidence: float 0..1 (how unique is this fingerprint?)
    notes:     human-readable description
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field


# ──────────────────────────────────────────────────────────────────────
# Computed primitives — derived from algorithm definitions
# ──────────────────────────────────────────────────────────────────────

def _gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) for AES."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8) — brute force is fine, 256 iterations."""
    if a == 0:
        return 0
    for i in range(1, 256):
        if _gf_mul(a, i) == 1:
            return i
    return 0


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xff


def aes_sbox() -> bytes:
    """AES forward S-box. 256 unique bytes — the gold standard fingerprint."""
    out = bytearray(256)
    for i in range(256):
        inv = _gf_inv(i)
        out[i] = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
    return bytes(out)


def aes_inv_sbox() -> bytes:
    """AES inverse S-box."""
    sbox = aes_sbox()
    out = bytearray(256)
    for i, s in enumerate(sbox):
        out[s] = i
    return bytes(out)


def aes_rcon() -> bytes:
    """AES round constants (10 entries used by AES-128)."""
    rcon = bytearray(11)
    rcon[1] = 1
    for i in range(2, 11):
        rcon[i] = _gf_mul(rcon[i - 1], 2)
    return bytes(rcon[1:])


def aes_te0() -> bytes:
    """AES T-table Te0 (used in fast bitsliced AES like OpenSSL).

    Te0[a] = [S[a]·2, S[a]·1, S[a]·1, S[a]·3] (4 bytes per entry, 1024 bytes total).
    """
    sbox = aes_sbox()
    out = bytearray()
    for i in range(256):
        s = sbox[i]
        word = struct.pack(
            ">BBBB",
            _gf_mul(s, 2), s, s, _gf_mul(s, 3),
        )
        out += word
    return bytes(out)


def sha256_k() -> bytes:
    """SHA-256 round constants K — 64 32-bit words from cube roots of primes."""
    primes = []
    n = 2
    while len(primes) < 64:
        is_prime = all(n % p for p in primes if p * p <= n)
        if is_prime:
            primes.append(n)
        n += 1
    out = bytearray()
    for p in primes:
        cube_root_frac = p ** (1 / 3) - int(p ** (1 / 3))
        out += struct.pack(">I", int(cube_root_frac * (1 << 32)) & 0xffffffff)
    return bytes(out)


def sha256_h() -> bytes:
    """SHA-256 init hash H — square roots of first 8 primes (BE)."""
    primes = [2, 3, 5, 7, 11, 13, 17, 19]
    out = bytearray()
    for p in primes:
        sqrt_frac = p ** 0.5 - int(p ** 0.5)
        out += struct.pack(">I", int(sqrt_frac * (1 << 32)) & 0xffffffff)
    return bytes(out)


def sha512_k() -> bytes:
    """SHA-512 round constants — 80 64-bit words (cube roots of first 80 primes)."""
    # mpmath would be ideal but we'll compute via known values.
    # These are the canonical SHA-512 K constants.
    k = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]
    return b"".join(struct.pack(">Q", v) for v in k)


def sha512_h() -> bytes:
    """SHA-512 init hash H (BE)."""
    h = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
    return b"".join(struct.pack(">Q", v) for v in h)


def sha1_h_be() -> bytes:
    """SHA-1 init hash (BE)."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    return b"".join(struct.pack(">I", v) for v in h)


def sha1_k_be() -> bytes:
    """SHA-1 round constants (4 values, BE) — concatenated."""
    k = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    return b"".join(struct.pack(">I", v) for v in k)


def md5_t() -> bytes:
    """MD5 T-table — int(abs(sin(i)) * 2^32) for i = 1..64."""
    out = bytearray()
    for i in range(1, 65):
        v = int(abs(math.sin(i)) * (1 << 32)) & 0xffffffff
        out += struct.pack("<I", v)
    return bytes(out)


def md5_h_le() -> bytes:
    """MD5 init hash (LE)."""
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    return b"".join(struct.pack("<I", v) for v in h)


def crc32_table(poly: int) -> bytes:
    """CRC-32 lookup table (256 entries, 4 bytes each = 1KB)."""
    out = bytearray()
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c >> 1) ^ poly) if (c & 1) else (c >> 1)
        out += struct.pack("<I", c)
    return bytes(out)


def des_sboxes() -> list[bytes]:
    """The 8 DES S-boxes — each 64 entries of 4 bits packed into bytes (low nibble)."""
    # Standard DES S-boxes
    s = [
        # S1
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
         0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
         4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
         15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        # S2
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
         3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
         0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
         13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        # S3
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
         13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
         13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
         1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        # S4
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
         13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
         10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
         3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        # S5
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
         14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
         4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
         11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        # S6
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
         10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
         9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
         4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        # S7
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
         13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
         1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
         6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        # S8
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
         1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
         7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
         2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ]
    # Pack each 4-bit entry into a byte. Many implementations store entries
    # as bytes (low nibble). Some pack 2 entries per byte. We'll emit the
    # byte-per-entry form which is the common compiled representation.
    return [bytes(box) for box in s]


def blowfish_p() -> bytes:
    """Blowfish P-array — 18 32-bit values from fractional pi.

    Stored both BE and LE in different implementations.
    """
    # Canonical Blowfish P-array
    p = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
        0x9216d5d9, 0x8979fb1b,
    ]
    return b"".join(struct.pack(">I", v) for v in p)


def blowfish_p_le() -> bytes:
    p = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
        0x9216d5d9, 0x8979fb1b,
    ]
    return b"".join(struct.pack("<I", v) for v in p)


def keccak_rc() -> bytes:
    """SHA-3 / Keccak round constants — 24 64-bit values (LE in most impls)."""
    rc = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    return b"".join(struct.pack("<Q", v) for v in rc)


def blake2b_iv() -> bytes:
    """BLAKE2b IV — same as SHA-512 H init (LE in BLAKE2)."""
    h = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
    return b"".join(struct.pack("<Q", v) for v in h)


def blake2s_iv() -> bytes:
    """BLAKE2s IV — same as SHA-256 H init (LE in BLAKE2)."""
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    return b"".join(struct.pack("<I", v) for v in h)


def md2_sbox() -> bytes:
    """MD2 substitution table — 256 bytes derived from pi digits."""
    return bytes([
        0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
        0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
        0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
        0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
        0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
        0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
        0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
        0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
        0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
        0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
        0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
        0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
        0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
        0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
        0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
        0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
    ])


# ──────────────────────────────────────────────────────────────────────
# Fingerprint catalog
# ──────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Fingerprint:
    name: str
    algorithm: str
    bytes: bytes
    endian: str = "any"        # "be" | "le" | "any"
    severity: str = "info"     # "ok" | "warn" | "critical" | "info" | "suspicious"
    confidence: float = 1.0
    notes: str = ""
    category: str = "primitive"  # "primitive" | "curve" | "table" | "marker"
    related: tuple = field(default_factory=tuple)  # related fingerprints (e.g. ECC parameters that come in groups)


def build_fingerprints() -> list[Fingerprint]:
    """Construct the full fingerprint database."""
    fps: list[Fingerprint] = []

    # ── AES ──
    fps += [
        Fingerprint("AES forward S-box", "aes", aes_sbox(), "any", "ok", 1.0,
                    "256-byte permutation. Definitive AES marker — present in nearly every AES implementation that isn't AES-NI-only.",
                    "table"),
        Fingerprint("AES inverse S-box", "aes", aes_inv_sbox(), "any", "ok", 1.0,
                    "Decryption S-box. Presence implies AES decrypt is implemented (vs. encrypt-only).",
                    "table"),
        Fingerprint("AES Te0 T-table", "aes", aes_te0(), "be", "ok", 0.95,
                    "Fast software AES table (OpenSSL-style). 1024 bytes.",
                    "table"),
    ]

    # ── SHA-2 ──
    fps += [
        Fingerprint("SHA-256 K constants", "sha256", sha256_k(), "be", "ok", 1.0,
                    "64 round constants from cube roots of primes (BE).",
                    "table"),
        Fingerprint("SHA-256 K constants (LE)", "sha256", sha256_k()[::-1] if False else
                    b"".join(struct.pack("<I", v) for v in struct.unpack(">"+"I"*64, sha256_k())),
                    "le", "ok", 0.95,
                    "Same K constants stored little-endian (Apple CoreCrypto, x86 native).",
                    "table"),
        Fingerprint("SHA-256 H init", "sha256", sha256_h(), "be", "ok", 0.9,
                    "Initial hash values from sqrt of first 8 primes.",
                    "primitive"),
        Fingerprint("SHA-512 K constants", "sha512", sha512_k(), "be", "ok", 1.0,
                    "80 round constants (64-bit). Distinct from SHA-256.",
                    "table"),
        Fingerprint("SHA-512 H init", "sha512", sha512_h(), "be", "ok", 0.9,
                    "Initial hash values for SHA-384/512.",
                    "primitive"),
    ]

    # ── SHA-1 (deprecated) ──
    fps += [
        Fingerprint("SHA-1 H init (BE)", "sha1", sha1_h_be(), "be", "warn", 0.85,
                    "BROKEN for collision resistance (SHAttered, 2017). Use SHA-256+.",
                    "primitive"),
        Fingerprint("SHA-1 H init (LE)", "sha1", b"".join(struct.pack("<I", v) for v in
                    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]),
                    "le", "warn", 0.7,
                    "SHA-1 init values stored little-endian. Note: shares first 4 words with MD5 H init — disambiguate with the 5th word C3D2E1F0.",
                    "primitive"),
        Fingerprint("SHA-1 K constants", "sha1", sha1_k_be(), "be", "warn", 0.7,
                    "4 SHA-1 round constants 5A827999..CA62C1D6.",
                    "table"),
    ]

    # ── MD5 (deprecated) ──
    fps += [
        Fingerprint("MD5 T-table", "md5", md5_t(), "le", "critical", 1.0,
                    "BROKEN. Pre-image attacks practical (2008). Used in tons of legacy TLS/IPSec code paths.",
                    "table"),
        Fingerprint("MD5 H init", "md5", md5_h_le(), "le", "critical", 0.6,
                    "MD5 init shares 4 words with SHA-1 init — combine with T-table presence to confirm.",
                    "primitive"),
    ]

    # ── ChaCha / Salsa ──
    fps += [
        Fingerprint("ChaCha20/Salsa20 sigma", "chacha20", b"expand 32-byte k", "any", "ok", 1.0,
                    "Quarter-round constant for 256-bit key. Identifies ChaCha20 (and Salsa20).",
                    "marker"),
        Fingerprint("ChaCha20/Salsa20 tau", "chacha20", b"expand 16-byte k", "any", "ok", 1.0,
                    "Quarter-round constant for 128-bit key.",
                    "marker"),
    ]

    # ── DES / 3DES (broken) ──
    for i, sbox in enumerate(des_sboxes(), start=1):
        fps.append(Fingerprint(
            f"DES S-box S{i}", "des", sbox, "any", "critical", 0.95,
            f"DES S-box {i}. DES is BROKEN (56-bit key brute-forceable in hours).",
            "table"))

    # ── Blowfish ──
    fps += [
        Fingerprint("Blowfish P-array (BE)", "blowfish", blowfish_p(), "be", "warn", 0.9,
                    "18 P-array values from pi. Blowfish is mostly fine cryptanalytically but has 64-bit blocks → birthday-bound issues (Sweet32).",
                    "table"),
        Fingerprint("Blowfish P-array (LE)", "blowfish", blowfish_p_le(), "le", "warn", 0.9,
                    "Same P-array, little-endian.",
                    "table"),
    ]

    # ── CRC (not crypto, but commonly mistaken / useful to identify) ──
    fps += [
        Fingerprint("CRC-32 IEEE table", "crc32", crc32_table(0xEDB88320), "le", "info", 0.95,
                    "Standard CRC-32 (zlib, PNG, Ethernet). Not cryptographic — flag if used as auth.",
                    "table"),
        Fingerprint("CRC-32C Castagnoli table", "crc32c", crc32_table(0x82F63B78), "le", "info", 0.95,
                    "CRC-32C (iSCSI, SCTP). Hardware-accelerated on x86 (CRC32 instruction) and ARM. Not cryptographic.",
                    "table"),
    ]

    # ── SHA-3 / Keccak ──
    fps += [
        Fingerprint("Keccak round constants", "sha3", keccak_rc(), "le", "ok", 1.0,
                    "24 round constants for SHA-3/Keccak-f[1600].",
                    "table"),
    ]

    # ── BLAKE2 ──
    fps += [
        Fingerprint("BLAKE2b IV", "blake2b", blake2b_iv(), "le", "ok", 0.7,
                    "BLAKE2b IV (same values as SHA-512 H, but stored LE). Disambiguate from SHA-512 by endian + nearby code patterns.",
                    "primitive"),
        Fingerprint("BLAKE2s IV", "blake2s", blake2s_iv(), "le", "ok", 0.7,
                    "BLAKE2s IV (SHA-256 H values stored LE).",
                    "primitive"),
    ]

    # ── MD2 (very deprecated) ──
    fps += [
        Fingerprint("MD2 substitution table", "md2", md2_sbox(), "any", "critical", 1.0,
                    "MD2 — BROKEN, deprecated in 2011. Should never appear in modern code.",
                    "table"),
    ]

    # ── ECC Curves ──
    # P-256 prime: 2^256 - 2^224 + 2^192 + 2^96 - 1
    p256_p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    p256_n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    p256_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    fps += [
        Fingerprint("P-256 prime", "p256", p256_p.to_bytes(32, "big"), "be", "ok", 1.0,
                    "NIST P-256 prime modulus. ECDSA/ECDH on this curve.",
                    "curve"),
        Fingerprint("P-256 prime (LE)", "p256", p256_p.to_bytes(32, "little"), "le", "ok", 1.0,
                    "P-256 prime, little-endian.",
                    "curve"),
        Fingerprint("P-256 group order", "p256", p256_n.to_bytes(32, "big"), "be", "ok", 0.95,
                    "P-256 base-point order n.",
                    "curve"),
        Fingerprint("P-256 b coefficient", "p256", p256_b.to_bytes(32, "big"), "be", "ok", 0.95,
                    "P-256 curve parameter b.",
                    "curve"),
    ]

    # secp256k1 (Bitcoin)
    sk_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    sk_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    sk_gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    fps += [
        Fingerprint("secp256k1 prime", "secp256k1", sk_p.to_bytes(32, "big"), "be", "ok", 1.0,
                    "Bitcoin/Ethereum curve prime. Suggests crypto wallet, signing, or blockchain code.",
                    "curve"),
        Fingerprint("secp256k1 group order", "secp256k1", sk_n.to_bytes(32, "big"), "be", "ok", 1.0,
                    "secp256k1 order n.",
                    "curve"),
        Fingerprint("secp256k1 base point Gx", "secp256k1", sk_gx.to_bytes(32, "big"), "be", "ok", 1.0,
                    "secp256k1 generator x-coordinate.",
                    "curve"),
        Fingerprint("secp256k1 prime (LE)", "secp256k1", sk_p.to_bytes(32, "little"), "le", "ok", 1.0,
                    "secp256k1 prime, little-endian.",
                    "curve"),
    ]

    # Curve25519 prime: 2^255 - 19
    c25_p = (1 << 255) - 19
    fps += [
        Fingerprint("Curve25519 prime (BE)", "curve25519", c25_p.to_bytes(32, "big"), "be", "ok", 0.9,
                    "Curve25519 / Ed25519 prime 2^255-19.",
                    "curve"),
        Fingerprint("Curve25519 prime (LE)", "curve25519", c25_p.to_bytes(32, "little"), "le", "ok", 0.9,
                    "Curve25519 prime, little-endian (Ref10/donna style).",
                    "curve"),
        # Ed25519 d constant: -121665 / 121666 (mod p) — just look for 121665 too
        Fingerprint("Ed25519 d constant marker", "ed25519",
                    (121665).to_bytes(8, "little") + b"",
                    "le", "ok", 0.4,
                    "Ed25519 uses 121665/121666 — heuristic, may match other things.",
                    "marker"),
    ]

    # ── TEA / XTEA ──
    fps += [
        Fingerprint("TEA/XTEA delta (BE)", "tea", (0x9E3779B9).to_bytes(4, "big"), "be", "warn", 0.4,
                    "TEA/XTEA round constant (golden ratio). Also appears in Java HashMap and many other places — low confidence on its own.",
                    "marker"),
        Fingerprint("TEA/XTEA delta (LE)", "tea", (0x9E3779B9).to_bytes(4, "little"), "le", "warn", 0.4,
                    "TEA/XTEA delta little-endian.",
                    "marker"),
    ]

    # ── RC2 ──
    fps += [
        Fingerprint("RC2 PITABLE", "rc2", bytes([
            0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
            0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
            0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
            0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
            0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
            0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
            0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
            0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
            0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
            0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
            0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
            0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
            0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
            0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
            0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
            0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
        ]), "any", "warn", 1.0,
            "RC2 PITABLE. RC2 has 64-bit blocks — Sweet32 vulnerable.",
            "table"),
    ]

    # ── Whirlpool ──
    # Whirlpool S-box - 256 bytes, well-defined permutation
    whirlpool_sbox = bytes([
        0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
        0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
        0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
        0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
        0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
        0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
        0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
        0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
        0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
        0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
        0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
        0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
        0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
        0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
        0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
        0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
    ])
    fps.append(Fingerprint("Whirlpool S-box", "whirlpool", whirlpool_sbox, "any", "ok", 1.0,
                           "Whirlpool hash S-box. Used in TrueCrypt/VeraCrypt and rarely elsewhere.",
                           "table"))

    # ── Markers / OIDs / formats ──
    fps += [
        Fingerprint("RSA OID (rsaEncryption 1.2.840.113549.1.1.1)", "rsa",
                    bytes.fromhex("06092a864886f70d010101"), "any", "ok", 0.95,
                    "ASN.1 OID for RSA. Indicates RSA key parsing.",
                    "marker"),
        Fingerprint("ECDSA-with-SHA256 OID", "ecdsa",
                    bytes.fromhex("06082a8648ce3d040302"), "any", "ok", 0.9,
                    "ASN.1 OID for ECDSA-with-SHA256.",
                    "marker"),
        Fingerprint("PKCS#1 v1.5 padding marker", "rsa",
                    b"\x00\x02", "any", "info", 0.1,
                    "Too short to flag — left for context.",
                    "marker"),
        Fingerprint("OpenSSL version magic", "openssl", b"OpenSSL ", "any", "ok", 0.6,
                    "OpenSSL version string fragment.",
                    "marker"),
        Fingerprint("LibreSSL version magic", "libressl", b"LibreSSL ", "any", "ok", 0.7,
                    "LibreSSL version string.",
                    "marker"),
        Fingerprint("BoringSSL marker", "boringssl", b"BoringSSL", "any", "ok", 0.9,
                    "Google BoringSSL.",
                    "marker"),
        Fingerprint("CommonCrypto marker", "commoncrypto", b"CommonCrypto", "any", "ok", 0.9,
                    "Apple CommonCrypto framework.",
                    "marker"),
    ]

    # ── HMAC ipad / opad ──
    # HMAC = H( (K XOR opad) || H( (K XOR ipad) || msg ) )
    # ipad = 0x36 repeated, opad = 0x5C repeated. Some implementations
    # compute K XOR opad / ipad on the fly; others precompute and store
    # the pads. Look for either ipad or opad as a long run of one byte.
    fps += [
        Fingerprint("HMAC ipad (64-byte block)", "hmac", b"\x36" * 64,
                    "any", "ok", 0.55,
                    "Inner pad for HMAC over a 64-byte block hash (MD5/SHA-1/SHA-256). "
                    "Long single-byte runs do appear elsewhere — combine with hash detection.",
                    "marker"),
        Fingerprint("HMAC opad (64-byte block)", "hmac", b"\x5c" * 64,
                    "any", "ok", 0.55,
                    "Outer pad for HMAC over a 64-byte block hash.",
                    "marker"),
        Fingerprint("HMAC ipad (128-byte block)", "hmac", b"\x36" * 128,
                    "any", "ok", 0.7,
                    "Inner pad for HMAC over a 128-byte block hash (SHA-512).",
                    "marker"),
        Fingerprint("HMAC opad (128-byte block)", "hmac", b"\x5c" * 128,
                    "any", "ok", 0.7,
                    "Outer pad for HMAC over a 128-byte block hash.",
                    "marker"),
    ]

    # ── AES Rcon (round constants for key schedule) ──
    fps += [
        Fingerprint("AES Rcon", "aes", aes_rcon(), "any", "ok", 0.6,
                    "AES key-schedule round constants. Short pattern — combine with S-box detection.",
                    "table"),
    ]

    # ── AES-GCM gHash polynomial constant ──
    # 0xe1 in highest byte, used in GHASH / GCM
    fps += [
        Fingerprint("AES-GCM GHASH polynomial",
                    "aes-gcm",
                    b"\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    "any", "ok", 0.5,
                    "GHASH irreducible polynomial 0xe1 (GCM mode). Short pattern, low confidence on its own.",
                    "marker"),
    ]

    # ── Poly1305 marker (clamping mask) ──
    # Poly1305 r-clamping ANDs the key bytes with: 0x0f ff ff fc 0f ff ff fc 0f ff ff fc 0f ff ff 0f
    # (in some byte order) — but it's often inlined as constants in code.
    # Slightly more reliable: the 2^130-5 prime modulus is harder to disguise.
    poly1305_clamp = bytes([0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc,
                             0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0x0f])
    fps += [
        Fingerprint("Poly1305 clamp mask", "poly1305", poly1305_clamp,
                    "any", "ok", 0.7,
                    "Poly1305 r-clamping mask. Combined with ChaCha20 detection → AEAD ChaCha20-Poly1305.",
                    "marker"),
    ]

    # ── Additional NIST curves ──
    # P-384
    p384_p = (1 << 384) - (1 << 128) - (1 << 96) + (1 << 32) - 1
    p384_n = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
    fps += [
        Fingerprint("P-384 prime", "p384", p384_p.to_bytes(48, "big"),
                    "be", "ok", 1.0,
                    "NIST P-384 prime modulus. Larger ECC curve.",
                    "curve"),
        Fingerprint("P-384 group order", "p384", p384_n.to_bytes(48, "big"),
                    "be", "ok", 1.0,
                    "P-384 base-point order n.",
                    "curve"),
    ]

    # P-521 (special — 521 bits = 66 bytes, top byte = 0x01)
    p521_p = (1 << 521) - 1
    fps += [
        Fingerprint("P-521 prime", "p521", p521_p.to_bytes(66, "big"),
                    "be", "ok", 0.95,
                    "NIST P-521 prime (Mersenne prime 2^521 - 1).",
                    "curve"),
    ]

    # Brainpool P256 r1 prime
    bp256_p = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
    fps += [
        Fingerprint("Brainpool P256r1 prime", "brainpool",
                    bp256_p.to_bytes(32, "big"), "be", "ok", 1.0,
                    "Brainpool P256r1 prime. Used in some EU/government applications.",
                    "curve"),
    ]

    # ── Password-hashing markers ──
    fps += [
        Fingerprint("scrypt marker string", "scrypt", b"$scrypt$",
                    "any", "ok", 0.85,
                    "scrypt encoded-hash prefix. Password hashing.",
                    "marker"),
        Fingerprint("Argon2 marker string", "argon2", b"$argon2",
                    "any", "ok", 0.95,
                    "Argon2 encoded-hash prefix (Argon2i/Argon2d/Argon2id).",
                    "marker"),
        Fingerprint("bcrypt marker string", "bcrypt", b"$2a$",
                    "any", "ok", 0.85,
                    "bcrypt encoded-hash prefix (also $2b$, $2y$).",
                    "marker"),
        Fingerprint("PBKDF2 marker string", "pbkdf2", b"PBKDF2",
                    "any", "ok", 0.7,
                    "PBKDF2 reference (often a function/symbol fragment).",
                    "marker"),
    ]

    # ── X9.63 / NIST KDF identifier ──
    fps += [
        Fingerprint("X9.63 KDF marker", "kdf", b"X9.63",
                    "any", "info", 0.5,
                    "ANSI X9.63 KDF reference.",
                    "marker"),
    ]

    # ── Bitcoin / Ethereum specific markers ──
    fps += [
    ]

    # ── RC4 detection (no constants — only structural heuristic) ──
    # RC4 has no fixed constants; we search for KSA pattern via its byte signatures
    # in the matchers module instead.

    # filter out anything with insufficient bytes (PKCS marker etc — too short to be useful as a search)
    fps = [f for f in fps if len(f.bytes) >= 4 or f.confidence >= 0.9]

    return fps


# Module-level cache built once
CRYPTO_FINGERPRINTS: list[Fingerprint] = build_fingerprints()
