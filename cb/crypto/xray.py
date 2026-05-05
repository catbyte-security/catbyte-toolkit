"""ASCII binary x-ray — single-screen visualization of file layout.

Each column = a fixed-width slice of the file. Rows show:
  - Section labels along the top (where they fit).
  - An entropy heatmap row using shaded block characters.
  - Crypto hits as colored markers below.
  - File offset ruler at the bottom.

The result fits in a few terminal lines and gives an immediate sense of
"where is the crypto in this binary?"
"""
from __future__ import annotations

import math
import os
from typing import Iterable

from cb.crypto.scanner import Hit, ScanResult, SectionInfo


# Density characters: ascending visual weight
_DENSITY = " .·-:=+*#%@"
# Block characters for entropy heatmap: light → dense
_HEAT = " ▁▂▃▄▅▆▇█"


def _entropy_chunk(data: bytes) -> float:
    """Shannon entropy of a chunk."""
    if not data:
        return 0.0
    from collections import Counter
    cnt = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in cnt.values() if v)


def _ansi(s: str, code: str, on: bool) -> str:
    if not on:
        return s
    return f"\033[{code}m{s}\033[0m"


# Map crypto algorithm to a single-char glyph.
_ALGO_GLYPH = {
    "aes":         "A",
    "aes-gcm":     "G",
    "des":         "D",
    "rc2":         "2",
    "rc4":         "4",
    "blowfish":    "B",
    "tea":         "T",
    "chacha20":    "C",
    "md5":         "5",
    "md2":         "M",
    "sha1":        "1",
    "sha256":      "S",
    "sha512":      "L",
    "sha3":        "K",
    "blake2b":     "b",
    "blake2s":     "s",
    "whirlpool":   "W",
    "p256":        "p",
    "p384":        "P",
    "p521":        "q",
    "secp256k1":   "k",
    "curve25519":  "c",
    "ed25519":     "e",
    "rsa":         "R",
    "ecdsa":       "E",
    "crc32":       ".",
    "crc32c":      ".",
    "hmac":        "h",
    "poly1305":    "y",
    "scrypt":      "x",
    "argon2":      "a",
    "bcrypt":      "z",
    "pbkdf2":      "n",
    "openssl":     "o",
    "libressl":    "o",
    "boringssl":   "o",
    "commoncrypto": "o",
}


# Algorithm color map — ANSI codes
_ALGO_COLOR = {
    "aes":        "32",        # green
    "aes-gcm":    "32",
    "des":        "31",        # red (broken)
    "rc2":        "33",        # yellow
    "rc4":        "31",
    "md5":        "31",
    "md2":        "31",
    "sha1":       "33",
    "sha256":     "32",
    "sha512":     "32",
    "sha3":       "32",
    "chacha20":   "36",        # cyan
    "p256":       "35",        # magenta
    "p384":       "35",
    "p521":       "35",
    "secp256k1":  "35",
    "curve25519": "35",
    "rsa":        "36",
    "ecdsa":      "36",
}


def render_xray(binary_path: str,
                 result: ScanResult,
                 width: int = 96,
                 color: bool = False) -> list[str]:
    """Render an ASCII x-ray of the binary. Returns lines.

    The visualization has 4 rows:
      1. Section name labels (where they fit)
      2. Entropy heatmap (block characters by density)
      3. Crypto hit markers (one per column, glyph by algorithm)
      4. Offset ruler (file offsets at column boundaries)
    """
    fs = result.file_size
    if fs == 0:
        return ["[empty file]"]

    bytes_per_col = max(1, fs // width)

    # Read the file in pieces — for big files we don't memmap to avoid
    # paging huge amounts; one read of a small uniform stride is fine.
    entropy = [0.0] * width
    with open(binary_path, "rb") as f:
        for col in range(width):
            off = col * bytes_per_col
            f.seek(off)
            chunk_size = min(bytes_per_col, fs - off, 8192)
            if chunk_size <= 0:
                break
            chunk = f.read(chunk_size)
            entropy[col] = _entropy_chunk(chunk)

    # Marker row: which crypto hits fall into which column
    markers = [None] * width  # type: ignore
    for h in result.hits:
        col = min(width - 1, h.file_offset // bytes_per_col)
        algo = h.fingerprint.algorithm
        # Library markers (openssl, etc.) clutter the view — skip them
        if algo in ("openssl", "libressl", "boringssl", "commoncrypto"):
            continue
        glyph = _ALGO_GLYPH.get(algo, "?")
        prev = markers[col]
        # Higher-severity hit wins the column (critical > warn > ok)
        if prev is None:
            markers[col] = (glyph, algo, h.fingerprint.severity)
        else:
            sev_rank = {"info": 0, "ok": 1, "warn": 2, "suspicious": 3, "critical": 4}
            if sev_rank.get(h.fingerprint.severity, 0) > sev_rank.get(prev[2], 0):
                markers[col] = (glyph, algo, h.fingerprint.severity)

    # Section label row — show first letter of each section name where it starts
    section_label = [" "] * width
    section_track = []  # for the 2nd label row showing section names
    if result.sections:
        # Pick out main sections to label: __text, __const, __cstring, __data
        important = []
        for s in result.sections:
            sg = (s.segment or "").lower()
            nm = (s.name or "").lower()
            if nm in ("__text", "__const", "__cstring", "__data", ".text",
                       ".rodata", ".data") or "text" in nm or "const" in nm:
                important.append(s)
        for s in important:
            start_col = min(width - 1, s.file_offset // bytes_per_col)
            end_col = min(width - 1, (s.file_offset + s.file_size) // bytes_per_col)
            # Place section initials at start; underscore through extent
            for col in range(start_col, min(end_col + 1, width)):
                if section_label[col] == " ":
                    section_label[col] = "─"
            # First letter of section at start_col
            if start_col < width:
                # Use the section name's first non-underscore letter
                nm = s.name.lstrip("_") or s.name
                section_label[start_col] = nm[0] if nm else "·"

    # Entropy row
    entropy_chars = []
    for e in entropy:
        idx = min(len(_HEAT) - 1, int(e / 8.0 * (len(_HEAT) - 1)))
        ch = _HEAT[idx]
        if color:
            # color by entropy: low=blue, mid=green, high=red
            if e < 3.0:
                ch = _ansi(ch, "34", True)
            elif e < 6.0:
                ch = _ansi(ch, "32", True)
            elif e < 7.5:
                ch = _ansi(ch, "33", True)
            else:
                ch = _ansi(ch, "31", True)
        entropy_chars.append(ch)
    entropy_row = "".join(entropy_chars)

    # Markers row
    marker_chars = []
    for m in markers:
        if m is None:
            marker_chars.append(" ")
        else:
            glyph, algo, sev = m
            ch = glyph
            if color:
                if sev == "critical":
                    ch = _ansi(ch, "1;31", True)
                elif sev == "warn":
                    ch = _ansi(ch, "33", True)
                else:
                    code = _ALGO_COLOR.get(algo, "32")
                    ch = _ansi(ch, code, True)
            marker_chars.append(ch)
    marker_row = "".join(marker_chars)

    # Section row
    section_row = "".join(section_label)

    # Ruler: show file offsets at five points
    ruler = [" "] * width
    for frac in (0, 0.25, 0.5, 0.75):
        col = int(frac * width)
        off = col * bytes_per_col
        label = f"0x{off:x}"
        for i, ch in enumerate(label):
            if col + i < width:
                ruler[col + i] = ch
    end_label = f"0x{fs:x}"
    for i, ch in enumerate(end_label):
        col = width - len(end_label) + i
        if 0 <= col < width:
            ruler[col] = ch
    ruler_row = "".join(ruler)

    # Legend
    used_algos = sorted({m[1] for m in markers if m is not None})
    legend_parts = []
    for a in used_algos:
        glyph = _ALGO_GLYPH.get(a, "?")
        if color:
            code = _ALGO_COLOR.get(a, "32")
            glyph = _ansi(glyph, code, True)
        legend_parts.append(f"{glyph}={a}")
    legend = "  ".join(legend_parts)

    out = [
        section_row,
        entropy_row,
        marker_row,
        ruler_row,
    ]
    if legend:
        out.append("")
        out.append(f"legend: {legend}")
    return out
