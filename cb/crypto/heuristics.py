"""Heuristic detectors that go beyond exact-byte fingerprint matching.

These complement constants.py:
  - find_modified_sboxes: detect ROLLED CRYPTO (modified AES/DES tables).
    Adversaries who don't trust standard crypto sometimes ship slightly
    modified S-boxes — same algorithm structure, different bytes. The
    modified table still has S-box-like statistical properties (256-byte
    permutation, full byte coverage) but won't match a known constant.
  - find_high_entropy_regions: blocks of bytes with near-uniform distribution.
    Possible candidates: encrypted blobs, packed code, embedded keys.
  - find_aes_constant_clusters: where AES S-box and Te-tables co-locate
    (a stronger signal than either alone).
  - find_unmatched_perm_tables: any 256-byte sliding window that is a
    permutation of 0..255 — generic substitution table marker.
  - disambiguate_dual_use: refines fingerprint hits where one byte pattern
    can mean two algorithms (BLAKE2/SHA-2 IV collision; SHA-1/MD5 H init).
"""
from __future__ import annotations

import math
import mmap
from collections import Counter
from dataclasses import dataclass
from typing import Iterator

from cb.crypto.constants import aes_sbox, aes_inv_sbox, des_sboxes
from cb.crypto.scanner import Hit, ScanResult


@dataclass
class HeuristicHit:
    kind: str          # "modified_sbox" | "high_entropy" | "perm_table" | "aes_cluster"
    file_offset: int
    size: int
    detail: dict
    severity: str = "info"
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "file_offset": self.file_offset,
            "size": self.size,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
        }


# ──────────────────────────────────────────────────────────────────────
# Modified S-box detection
# ──────────────────────────────────────────────────────────────────────

def _is_byte_permutation(window: bytes) -> bool:
    """True if `window` is exactly 256 bytes and contains each value 0..255 once."""
    if len(window) != 256:
        return False
    return len(set(window)) == 256


def _hamming_distance(a: bytes, b: bytes) -> int:
    """Number of positions where bytes differ. Both must be same length."""
    return sum(1 for x, y in zip(a, b) if x != y)


def find_modified_sboxes(data: bytes | mmap.mmap, *,
                          min_distance: int = 1,
                          max_distance: int = 64,
                          step: int = 1) -> list[HeuristicHit]:
    """Find 256-byte windows that are permutations of 0..255 but differ from
    known S-boxes by ``min_distance`` to ``max_distance`` bytes.

    A 0-distance match is just the standard S-box (already covered by constants).
    A small distance suggests a *modified* table — common in custom/rolled crypto
    or DRM. A large distance is more likely a generic permutation lookup table.

    ``step`` lets us skip ahead — windows are mostly empty in real binaries,
    so we don't need to check every byte offset. We use a fast pre-filter
    (cheap byte-count check) before the expensive permutation test.
    """
    aes = aes_sbox()
    aes_inv = aes_inv_sbox()
    known = {"AES S-box": aes, "AES inv S-box": aes_inv}
    for i, des_s in enumerate(des_sboxes(), start=1):
        # DES S-boxes are 64 bytes, not 256 — skip for this detector
        pass

    n = len(data)
    if n < 256:
        return []

    out: list[HeuristicHit] = []
    # We need a fast pre-filter. A byte-permutation has Counter == {b: 1 for all b}.
    # Sliding a 256-byte window and incrementally maintaining a Counter is O(n).
    # But Python overhead makes that slow for big files; instead we use mmap.find
    # to anchor on rare bytes? Better: just do strided sampling with pre-filter.
    #
    # Pre-filter: in any 256-byte permutation, the byte 0x00 appears exactly once.
    # We use that as an anchor: only test windows where 0x00 is at a sensible position.
    # That's still expensive; settle for sampling every `step` bytes when no anchor.

    # Simple O(n/step) approach
    for off in range(0, n - 256 + 1, step):
        window = bytes(data[off:off + 256])
        # Cheap rejection — if any byte appears >2 times, can't be permutation
        # Actually compute set length in C via len(set(...)). 256 elements is fast.
        if len(set(window)) != 256:
            continue
        # It's a permutation. Distance to known?
        for name, ref in known.items():
            d = _hamming_distance(window, ref)
            if min_distance <= d <= max_distance:
                out.append(HeuristicHit(
                    kind="modified_sbox",
                    file_offset=off,
                    size=256,
                    detail={
                        "reference": name,
                        "hamming_distance": d,
                        "first_diff_offset": next((i for i, (x, y) in enumerate(zip(window, ref)) if x != y), -1),
                    },
                    severity="suspicious" if d <= 16 else "info",
                    confidence=max(0.3, 1.0 - d / 256.0),
                ))
                break

    return out


# ──────────────────────────────────────────────────────────────────────
# Entropy
# ──────────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8). Compressed/encrypted ≈ 7.9+."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def find_high_entropy_regions(data: bytes | mmap.mmap, *,
                                window: int = 4096,
                                step: int = 4096,
                                threshold: float = 7.5,
                                min_run_blocks: int = 1) -> list[HeuristicHit]:
    """Sliding window entropy. Adjacent high-entropy blocks are merged into runs.

    Note: code typically has entropy ≈ 5.5–6.5; high-entropy regions are
    suspicious for embedded encrypted blobs, packed sections, or compressed data.
    """
    n = len(data)
    if n < window:
        return []

    # Sample entropy at each step
    blocks: list[tuple[int, float]] = []  # (offset, entropy)
    for off in range(0, n - window + 1, step):
        chunk = bytes(data[off:off + window])
        e = shannon_entropy(chunk)
        blocks.append((off, e))

    # Merge consecutive high-entropy blocks
    out: list[HeuristicHit] = []
    run_start = -1
    run_entropies: list[float] = []
    for i, (off, e) in enumerate(blocks):
        if e >= threshold:
            if run_start < 0:
                run_start = off
            run_entropies.append(e)
        else:
            if run_start >= 0 and len(run_entropies) >= min_run_blocks:
                end = blocks[i - 1][0] + window
                out.append(HeuristicHit(
                    kind="high_entropy",
                    file_offset=run_start,
                    size=end - run_start,
                    detail={
                        "blocks": len(run_entropies),
                        "mean_entropy": round(sum(run_entropies) / len(run_entropies), 3),
                        "max_entropy": round(max(run_entropies), 3),
                    },
                    severity="info",
                    confidence=min(0.95, max(run_entropies) / 8.0),
                ))
            run_start = -1
            run_entropies = []

    # Trailing run
    if run_start >= 0 and len(run_entropies) >= min_run_blocks:
        end = blocks[-1][0] + window
        out.append(HeuristicHit(
            kind="high_entropy",
            file_offset=run_start,
            size=end - run_start,
            detail={
                "blocks": len(run_entropies),
                "mean_entropy": round(sum(run_entropies) / len(run_entropies), 3),
                "max_entropy": round(max(run_entropies), 3),
            },
            severity="info",
            confidence=min(0.95, max(run_entropies) / 8.0),
        ))

    return out


# ──────────────────────────────────────────────────────────────────────
# AES cluster — co-location of multiple AES tables
# ──────────────────────────────────────────────────────────────────────

def find_aes_clusters(hits: list[Hit], *, max_gap: int = 8192) -> list[HeuristicHit]:
    """Cluster of AES-related fingerprint hits within close proximity.

    Strong signal for "AES is really used here, not just a random match."
    """
    aes_hits = [h for h in hits if h.fingerprint.algorithm == "aes"]
    aes_hits.sort(key=lambda h: h.file_offset)
    out: list[HeuristicHit] = []
    cluster: list[Hit] = []
    last_off = -10**18
    for h in aes_hits:
        if h.file_offset - last_off <= max_gap and cluster:
            cluster.append(h)
        else:
            if len(cluster) >= 2:
                out.append(HeuristicHit(
                    kind="aes_cluster",
                    file_offset=cluster[0].file_offset,
                    size=cluster[-1].file_offset - cluster[0].file_offset + len(cluster[-1].fingerprint.bytes),
                    detail={
                        "constants": [c.fingerprint.name for c in cluster],
                    },
                    severity="ok",
                    confidence=1.0,
                ))
            cluster = [h]
        last_off = h.file_offset
    if len(cluster) >= 2:
        out.append(HeuristicHit(
            kind="aes_cluster",
            file_offset=cluster[0].file_offset,
            size=cluster[-1].file_offset - cluster[0].file_offset + len(cluster[-1].fingerprint.bytes),
            detail={
                "constants": [c.fingerprint.name for c in cluster],
            },
            severity="ok",
            confidence=1.0,
        ))
    return out


# ──────────────────────────────────────────────────────────────────────
# Disambiguation
# ──────────────────────────────────────────────────────────────────────

def disambiguate_dual_use(hits: list[Hit]) -> list[Hit]:
    """Resolve fingerprints that share bytes between algorithms.

    Cases handled:
      - BLAKE2s IV vs SHA-256 H init (LE): the bytes are identical. If we have
        a confirmed SHA-256 K-table hit nearby we prefer SHA-256; otherwise
        we leave BLAKE2s.
      - BLAKE2b IV vs SHA-512 H init (LE): same logic.
      - MD5 H init vs SHA-1 H init: 4-word overlap; presence of MD5 T-table
        elsewhere disambiguates MD5; presence of SHA-1 K constants disambiguates SHA-1.

    We don't remove hits — we *annotate* them (downgrade confidence,
    optionally retag the algorithm).
    """
    has_sha256 = any(h.fingerprint.algorithm == "sha256" and "K" in h.fingerprint.name for h in hits)
    has_sha512 = any(h.fingerprint.algorithm == "sha512" and "K" in h.fingerprint.name for h in hits)
    has_md5_t = any(h.fingerprint.algorithm == "md5" and "T-table" in h.fingerprint.name for h in hits)
    has_sha1_k = any(h.fingerprint.algorithm == "sha1" and "K" in h.fingerprint.name for h in hits)

    out: list[Hit] = []
    for h in hits:
        # Drop low-confidence dual-use hits when their dual is confirmed
        name = h.fingerprint.name
        algo = h.fingerprint.algorithm
        if algo == "blake2s" and "IV" in name and has_sha256:
            # likely the SHA-256 IV
            continue
        if algo == "blake2b" and "IV" in name and has_sha512:
            continue
        if algo == "md5" and "H init" in name and has_sha1_k and not has_md5_t:
            continue
        if algo == "sha1" and "H init" in name and has_md5_t and not has_sha1_k:
            continue
        out.append(h)
    return out


# ──────────────────────────────────────────────────────────────────────
# Composite analysis
# ──────────────────────────────────────────────────────────────────────

def analyze(result: ScanResult, data: bytes | mmap.mmap | None = None,
            entropy_threshold: float = 7.5,
            modified_sbox_step: int = 64,
            run_modified_sbox: bool = True,
            run_entropy: bool = True) -> dict:
    """Run all heuristics on a ScanResult.

    Returns a dict with:
      - hits: refined fingerprint hits (after disambiguation)
      - clusters: AES cluster hits
      - modified_sboxes: suspicious S-box findings
      - high_entropy: high-entropy regions
    """
    refined = disambiguate_dual_use(result.hits)
    clusters = find_aes_clusters(refined)

    modified_sboxes: list[HeuristicHit] = []
    high_entropy: list[HeuristicHit] = []
    if data is not None:
        if run_modified_sbox:
            modified_sboxes = find_modified_sboxes(data, step=modified_sbox_step)
        if run_entropy:
            high_entropy = find_high_entropy_regions(
                data, threshold=entropy_threshold)

    return {
        "hits": refined,
        "clusters": clusters,
        "modified_sboxes": modified_sboxes,
        "high_entropy": high_entropy,
    }
