"""Tests for cb crypto - cryptographic primitive detection."""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────
# Constants integrity — these must compute to the canonical RFC values
# ──────────────────────────────────────────────────────────────────────

class TestAESConstants:
    def test_sbox_canonical_first_16(self):
        from cb.crypto.constants import aes_sbox
        s = aes_sbox()
        # FIPS-197 §5.1.1 / canonical first 16 bytes
        assert s[:16].hex() == "637c777bf26b6fc53001672bfed7ab76"

    def test_sbox_is_permutation(self):
        from cb.crypto.constants import aes_sbox
        s = aes_sbox()
        assert len(s) == 256
        assert sorted(s) == list(range(256))

    def test_inv_sbox_inverts_sbox(self):
        from cb.crypto.constants import aes_sbox, aes_inv_sbox
        s = aes_sbox()
        inv = aes_inv_sbox()
        for i in range(256):
            assert inv[s[i]] == i, f"inverse failed at byte {i}"

    def test_te_table_size(self):
        from cb.crypto.constants import aes_te0
        assert len(aes_te0()) == 1024


class TestSHAConstants:
    def test_sha256_k_first_value(self):
        # First K constant should be 0x428a2f98 (BE)
        from cb.crypto.constants import sha256_k
        k = sha256_k()
        assert k[:4].hex() == "428a2f98"
        assert len(k) == 64 * 4

    def test_sha256_h_first_value(self):
        # H[0] should be 0x6a09e667 (BE)
        from cb.crypto.constants import sha256_h
        h = sha256_h()
        assert h[:4].hex() == "6a09e667"

    def test_sha512_k_size(self):
        from cb.crypto.constants import sha512_k
        assert len(sha512_k()) == 80 * 8

    def test_sha1_h_init_be(self):
        from cb.crypto.constants import sha1_h_be
        h = sha1_h_be()
        # H[0] = 0x67452301 BE
        assert h[:4].hex() == "67452301"
        assert h[16:20].hex() == "c3d2e1f0"  # 5th word


class TestMD5Constants:
    def test_md5_t_first_value_rfc1321(self):
        # RFC 1321: T[1] = 0xd76aa478, stored LE → 78a46ad7
        from cb.crypto.constants import md5_t
        t = md5_t()
        assert t[:4].hex() == "78a46ad7"
        assert len(t) == 64 * 4


class TestCRCConstants:
    def test_ieee_polynomial_first_4_entries(self):
        from cb.crypto.constants import crc32_table
        ieee = crc32_table(0xEDB88320)
        # First 4 entries: 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA
        # Stored LE
        assert ieee[:4] == b"\x00\x00\x00\x00"
        assert ieee[4:8] == struct.pack("<I", 0x77073096)
        assert len(ieee) == 256 * 4

    def test_castagnoli_differs_from_ieee(self):
        from cb.crypto.constants import crc32_table
        ieee = crc32_table(0xEDB88320)
        cast = crc32_table(0x82F63B78)
        assert ieee != cast


class TestFingerprintCatalog:
    def test_database_built(self):
        from cb.crypto.constants import CRYPTO_FINGERPRINTS
        assert len(CRYPTO_FINGERPRINTS) > 30

    def test_all_fingerprints_have_bytes(self):
        from cb.crypto.constants import CRYPTO_FINGERPRINTS
        for fp in CRYPTO_FINGERPRINTS:
            assert len(fp.bytes) >= 4, f"{fp.name} too short"

    def test_severities_are_valid(self):
        from cb.crypto.constants import CRYPTO_FINGERPRINTS
        valid = {"info", "ok", "warn", "critical", "suspicious"}
        for fp in CRYPTO_FINGERPRINTS:
            assert fp.severity in valid

    def test_aes_sbox_in_catalog(self):
        from cb.crypto.constants import CRYPTO_FINGERPRINTS, aes_sbox
        s = aes_sbox()
        assert any(fp.bytes == s for fp in CRYPTO_FINGERPRINTS)


# ──────────────────────────────────────────────────────────────────────
# Scanner — synthetic binaries with known content
# ──────────────────────────────────────────────────────────────────────

class TestScanner:
    def test_finds_aes_sbox_in_synthetic_blob(self, tmp_path):
        from cb.crypto.scanner import scan_binary
        from cb.crypto.constants import aes_sbox
        f = tmp_path / "blob.bin"
        # AES S-box surrounded by random padding
        f.write_bytes(b"\xab" * 100 + aes_sbox() + b"\xcd" * 100)
        r = scan_binary(str(f))
        algos = {h.fingerprint.algorithm for h in r.hits}
        assert "aes" in algos

    def test_finds_sha256_constants(self, tmp_path):
        from cb.crypto.scanner import scan_binary
        from cb.crypto.constants import sha256_k
        f = tmp_path / "blob.bin"
        f.write_bytes(b"\x00" * 50 + sha256_k() + b"\x00" * 50)
        r = scan_binary(str(f))
        algos = {h.fingerprint.algorithm for h in r.hits}
        assert "sha256" in algos

    def test_chacha_sigma_string(self, tmp_path):
        from cb.crypto.scanner import scan_binary
        f = tmp_path / "blob.bin"
        f.write_bytes(b"junk" + b"expand 32-byte k" + b"junk")
        r = scan_binary(str(f))
        algos = {h.fingerprint.algorithm for h in r.hits}
        assert "chacha20" in algos

    def test_empty_file(self, tmp_path):
        from cb.crypto.scanner import scan_binary
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        r = scan_binary(str(f))
        assert r.hits == []
        assert r.file_size == 0

    def test_no_crypto(self, tmp_path):
        from cb.crypto.scanner import scan_binary
        f = tmp_path / "boring.bin"
        # plain ASCII text — no crypto constants
        f.write_bytes(b"the quick brown fox " * 100)
        r = scan_binary(str(f))
        # may match low-confidence markers, but no high-confidence algorithms
        crypto_algos = {h.fingerprint.algorithm for h in r.hits
                         if h.fingerprint.severity in ("ok", "warn", "critical")
                         and h.fingerprint.algorithm not in ("openssl", "libressl", "boringssl")}
        assert not crypto_algos

    def test_max_hits_per_pattern_caps_results(self, tmp_path):
        from cb.crypto.scanner import scan_binary
        from cb.crypto.constants import aes_sbox
        f = tmp_path / "many.bin"
        # Repeat the AES S-box 10 times
        f.write_bytes(aes_sbox() * 10)
        r = scan_binary(str(f), max_hits_per_pattern=3)
        sbox_hits = [h for h in r.hits if h.fingerprint.name == "AES forward S-box"]
        assert len(sbox_hits) == 3


# ──────────────────────────────────────────────────────────────────────
# Heuristics
# ──────────────────────────────────────────────────────────────────────

class TestHeuristics:
    def test_shannon_entropy_uniform(self):
        from cb.crypto.heuristics import shannon_entropy
        # Uniform random ≈ 8.0 (we approximate with 0..255 once each)
        data = bytes(range(256)) * 16
        e = shannon_entropy(data)
        assert 7.99 <= e <= 8.001

    def test_shannon_entropy_constant(self):
        from cb.crypto.heuristics import shannon_entropy
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_modified_sbox_detection(self):
        from cb.crypto.heuristics import find_modified_sboxes
        from cb.crypto.constants import aes_sbox
        # Take AES S-box, swap two bytes — distance = 2
        s = bytearray(aes_sbox())
        s[0], s[1] = s[1], s[0]
        data = b"\x00" * 100 + bytes(s) + b"\x00" * 100
        out = find_modified_sboxes(data, step=1, min_distance=1, max_distance=64)
        assert len(out) >= 1
        assert out[0].detail["reference"] == "AES S-box"
        assert out[0].detail["hamming_distance"] == 2

    def test_unmodified_sbox_not_flagged(self):
        from cb.crypto.heuristics import find_modified_sboxes
        from cb.crypto.constants import aes_sbox
        # Standard S-box — distance 0, must NOT be flagged
        data = b"\x00" * 100 + aes_sbox() + b"\x00" * 100
        out = find_modified_sboxes(data, step=1, min_distance=1, max_distance=64)
        assert len(out) == 0

    def test_high_entropy_region(self, tmp_path):
        from cb.crypto.heuristics import find_high_entropy_regions
        # Build a region of pseudo-random bytes
        import os as _os
        data = b"\x00" * 8192 + _os.urandom(16384) + b"\x00" * 8192
        out = find_high_entropy_regions(data, window=4096, step=4096, threshold=7.0)
        # At least one region of high entropy in the middle
        assert len(out) >= 1
        # The detected region overlaps the random middle (8192..24576)
        assert any(8000 <= h.file_offset < 24576 for h in out)

    def test_disambiguate_blake2_vs_sha(self):
        # BLAKE2s IV bytes == SHA-256 H init bytes (LE).
        # If we have SHA-256 K constants confirmed, the IV hit should be
        # interpreted as SHA-256 not BLAKE2s.
        from cb.crypto.constants import CRYPTO_FINGERPRINTS
        from cb.crypto.scanner import Hit
        from cb.crypto.heuristics import disambiguate_dual_use

        sha256_k = next(f for f in CRYPTO_FINGERPRINTS
                        if f.algorithm == "sha256" and "K constants" in f.name)
        blake2s_iv = next(f for f in CRYPTO_FINGERPRINTS
                          if f.algorithm == "blake2s" and "IV" in f.name)
        hits = [Hit(sha256_k, 100), Hit(blake2s_iv, 200)]
        out = disambiguate_dual_use(hits)
        # blake2s IV should be dropped since SHA-256 K is present
        assert all(h.fingerprint.algorithm != "blake2s" for h in out)

    def test_aes_cluster(self):
        from cb.crypto.constants import CRYPTO_FINGERPRINTS
        from cb.crypto.scanner import Hit
        from cb.crypto.heuristics import find_aes_clusters
        aes_fps = [f for f in CRYPTO_FINGERPRINTS if f.algorithm == "aes"][:3]
        # Place 3 AES hits within 1KB of each other
        hits = [Hit(aes_fps[0], 1000),
                Hit(aes_fps[1], 1500),
                Hit(aes_fps[2], 2000)]
        clusters = find_aes_clusters(hits, max_gap=2000)
        assert len(clusters) == 1
        assert len(clusters[0].detail["constants"]) == 3


# ──────────────────────────────────────────────────────────────────────
# Report — verdict logic
# ──────────────────────────────────────────────────────────────────────

class TestReport:
    def test_overall_verdict_critical_when_md5(self):
        from cb.crypto.report import overall_verdict
        algos = [
            {"algorithm": "md5", "verdict": "critical", "family": "hash"},
            {"algorithm": "aes", "verdict": "ok", "family": "block-cipher"},
        ]
        v = overall_verdict(algos)
        assert v["verdict"] == "critical"
        assert "md5" in v["message"]

    def test_overall_verdict_warn_when_sha1(self):
        from cb.crypto.report import overall_verdict
        algos = [
            {"algorithm": "sha1", "verdict": "warn", "family": "hash"},
            {"algorithm": "aes", "verdict": "ok", "family": "block-cipher"},
        ]
        v = overall_verdict(algos)
        assert v["verdict"] == "warn"

    def test_overall_verdict_ok_when_modern(self):
        from cb.crypto.report import overall_verdict
        algos = [
            {"algorithm": "aes", "verdict": "ok", "family": "block-cipher"},
            {"algorithm": "sha256", "verdict": "ok", "family": "hash"},
        ]
        v = overall_verdict(algos)
        assert v["verdict"] == "ok"

    def test_library_marker_alone_doesnt_make_critical(self):
        # commoncrypto is "info" — should not move us out of "info"
        from cb.crypto.report import overall_verdict
        algos = [{"algorithm": "openssl", "verdict": "info", "family": "library-marker"}]
        v = overall_verdict(algos)
        assert v["verdict"] == "info"

    def test_text_report_renders(self):
        from cb.crypto.report import render_text
        d = {
            "binary": "/x", "format": "macho", "architecture": "arm64",
            "file_size": 1000, "scan_seconds": 0.01,
            "verdict": {"verdict": "ok", "message": "all good",
                        "counts": {"critical": 0, "warn": 0, "ok": 1}},
            "summary": {"weak_or_broken": []},
            "algorithms": [{
                "algorithm": "aes", "family": "block-cipher", "verdict": "ok",
                "rationale": "test", "max_severity": "ok", "confidence": 1.0,
                "evidence_count": 1, "evidence_kinds": ["AES S-box"],
                "sample_locations": [{"file_offset": 0, "section": "__const",
                                      "segment": "__TEXT",
                                      "virtual_address": "0x1000"}],
            }],
            "heuristics": {"aes_clusters": [], "modified_sboxes": [],
                           "high_entropy_regions": []},
        }
        out = render_text(d, color=False)
        assert "cryptid" in out
        assert "aes" in out
        assert "AES S-box" in out

    def test_markdown_report_renders(self):
        from cb.crypto.report import render_markdown
        d = {
            "binary": "/x", "format": "macho", "architecture": "arm64",
            "file_size": 1000, "scan_seconds": 0.01,
            "verdict": {"verdict": "critical", "message": "broken",
                        "counts": {"critical": 1, "warn": 0, "ok": 0}},
            "summary": {"weak_or_broken": ["md5"]},
            "algorithms": [{
                "algorithm": "md5", "family": "hash", "verdict": "critical",
                "rationale": "broken", "confidence": 1.0,
                "evidence_count": 1, "evidence_kinds": ["MD5 T-table"],
            }],
            "heuristics": {"aes_clusters": [], "modified_sboxes": [],
                           "high_entropy_regions": []},
        }
        out = render_markdown(d)
        assert "# cryptid" in out
        assert "CRITICAL" in out
        assert "md5" in out


# ──────────────────────────────────────────────────────────────────────
# Integration smoke test (skipped if expected fixtures absent)
# ──────────────────────────────────────────────────────────────────────

class TestIntegration:
    @pytest.mark.skipif(
        not os.path.exists("/opt/homebrew/opt/libsodium/lib/libsodium.26.dylib"),
        reason="libsodium not installed",
    )
    def test_libsodium_detects_known_algorithms(self):
        from cb.crypto.scanner import scan_binary
        from cb.crypto.heuristics import disambiguate_dual_use
        r = scan_binary("/opt/homebrew/opt/libsodium/lib/libsodium.26.dylib")
        algos = {h.fingerprint.algorithm for h in disambiguate_dual_use(r.hits)}
        # libsodium implements these — they MUST be detected
        for must_have in ("chacha20", "curve25519", "aes"):
            assert must_have in algos, f"libsodium missing {must_have} detection"

    @pytest.mark.skipif(
        not os.path.exists("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"),
        reason="openssl@3 not installed",
    )
    def test_libcrypto_format_macho(self):
        from cb.crypto.scanner import scan_binary
        r = scan_binary("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib")
        assert r.format == "macho"
        assert r.architecture in ("arm64", "x86_64")
        assert len(r.sections) > 0
