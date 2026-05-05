"""Risk scoring and human-readable report formatting."""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from typing import Iterable

from cb.crypto.scanner import Hit, ScanResult
from cb.crypto.heuristics import HeuristicHit


# ──────────────────────────────────────────────────────────────────────
# Algorithm metadata for risk scoring
# ──────────────────────────────────────────────────────────────────────

# Severity ordering: higher = more concerning
SEVERITY_RANK = {"info": 0, "ok": 1, "warn": 2, "suspicious": 3, "critical": 4}

ALGO_INFO = {
    "aes":         {"family": "block-cipher",  "verdict": "ok",       "reason": "Symmetric standard. Mode/IV usage matters."},
    "des":         {"family": "block-cipher",  "verdict": "critical", "reason": "BROKEN. 56-bit keyspace. Replace with AES."},
    "blowfish":    {"family": "block-cipher",  "verdict": "warn",     "reason": "64-bit blocks → Sweet32 vulnerable. Replace with AES or ChaCha20."},
    "rc2":         {"family": "block-cipher",  "verdict": "warn",     "reason": "64-bit blocks. Mostly legacy CMS/PKCS#7 code. Avoid in new designs."},
    "tea":         {"family": "block-cipher",  "verdict": "warn",     "reason": "Has known equivalent-key issues. XTEA fixes some but Sweet32 still applies. Verify usage."},
    "chacha20":    {"family": "stream-cipher", "verdict": "ok",       "reason": "Modern stream cipher. Watch for nonce reuse."},
    "rc4":         {"family": "stream-cipher", "verdict": "critical", "reason": "BROKEN. Bias attacks practical. Forbidden in TLS since 2015."},
    "md5":         {"family": "hash",          "verdict": "critical", "reason": "BROKEN for collisions and pre-image attacks. Use only for non-security checksums."},
    "md2":         {"family": "hash",          "verdict": "critical", "reason": "BROKEN. Should not appear in modern code."},
    "sha1":        {"family": "hash",          "verdict": "warn",     "reason": "Collision-broken (SHAttered, 2017). Avoid for signatures and HMAC; OK for HMAC-only legacy."},
    "sha256":      {"family": "hash",          "verdict": "ok",       "reason": "Strong general-purpose hash."},
    "sha512":      {"family": "hash",          "verdict": "ok",       "reason": "Strong; faster than SHA-256 on 64-bit machines."},
    "sha3":        {"family": "hash",          "verdict": "ok",       "reason": "Different construction (sponge); good defense-in-depth choice."},
    "blake2b":     {"family": "hash",          "verdict": "ok",       "reason": "Fast, modern hash. Often used for HMAC replacement."},
    "blake2s":     {"family": "hash",          "verdict": "ok",       "reason": "BLAKE2 for 32-bit platforms."},
    "whirlpool":   {"family": "hash",          "verdict": "ok",       "reason": "Used by TrueCrypt/VeraCrypt; fine cryptographically but rarely seen elsewhere."},
    "crc32":       {"family": "checksum",      "verdict": "info",     "reason": "Not cryptographic. CRITICAL if used as auth or integrity check on adversarial input."},
    "crc32c":      {"family": "checksum",      "verdict": "info",     "reason": "Not cryptographic. Hardware-accelerated."},
    "p256":        {"family": "ecc",           "verdict": "ok",       "reason": "NIST P-256 curve. Watch for non-constant-time scalar multiplication."},
    "secp256k1":   {"family": "ecc",           "verdict": "ok",       "reason": "Bitcoin/Ethereum. Strong but small implementations risk side-channel leaks."},
    "curve25519":  {"family": "ecc",           "verdict": "ok",       "reason": "Modern, side-channel-resistant ECDH curve."},
    "ed25519":     {"family": "ecc",           "verdict": "ok",       "reason": "Modern signature curve."},
    "rsa":         {"family": "asymmetric",    "verdict": "ok",       "reason": "Strong if ≥2048 bits with proper padding (OAEP/PSS)."},
    "ecdsa":       {"family": "asymmetric",    "verdict": "ok",       "reason": "Watch for nonce-reuse — single reuse leaks the private key."},
    "openssl":     {"family": "library-marker", "verdict": "info",    "reason": "OpenSSL library detected."},
    "libressl":    {"family": "library-marker", "verdict": "info",    "reason": "LibreSSL library detected."},
    "boringssl":   {"family": "library-marker", "verdict": "info",    "reason": "BoringSSL library detected."},
    "commoncrypto":{"family": "library-marker", "verdict": "info",    "reason": "Apple CommonCrypto detected."},
}


def algo_info(algo: str) -> dict:
    return ALGO_INFO.get(algo, {"family": "unknown", "verdict": "info", "reason": ""})


# ──────────────────────────────────────────────────────────────────────
# Aggregation
# ──────────────────────────────────────────────────────────────────────

def aggregate(result: ScanResult, refined_hits: list[Hit]) -> dict:
    """Group hits by algorithm and compute the verdict."""
    by_algo: dict[str, list[Hit]] = defaultdict(list)
    for h in refined_hits:
        by_algo[h.fingerprint.algorithm].append(h)

    algorithms = []
    for algo, hits in sorted(by_algo.items(), key=lambda kv: (-max(SEVERITY_RANK[h.fingerprint.severity] for h in kv[1]), kv[0])):
        info = algo_info(algo)
        # use max severity among hits; if any hit confidence ≥ 0.9, mark "high"
        hit_severities = [h.fingerprint.severity for h in hits]
        max_sev = max(hit_severities, key=lambda s: SEVERITY_RANK[s])
        confidence = max(h.fingerprint.confidence for h in hits)
        evidence = sorted({h.fingerprint.name for h in hits})
        sample_locations = []
        for h in hits[:3]:
            loc = {
                "file_offset": h.file_offset,
                "section": h.section,
                "segment": h.segment,
            }
            if h.virtual_address is not None:
                loc["virtual_address"] = f"0x{h.virtual_address:x}"
            sample_locations.append(loc)
        algorithms.append({
            "algorithm": algo,
            "family": info["family"],
            "verdict": info["verdict"],
            "rationale": info["reason"],
            "max_severity": max_sev,
            "confidence": round(confidence, 2),
            "evidence_count": len(hits),
            "evidence_kinds": evidence,
            "sample_locations": sample_locations,
        })
    return {"algorithms": algorithms, "by_algo": by_algo}


def overall_verdict(algorithms: list[dict]) -> dict:
    """Compute a single-line verdict for the binary."""
    crit = [a for a in algorithms if a["verdict"] == "critical" and a["family"] != "library-marker"]
    warn = [a for a in algorithms if a["verdict"] == "warn"]
    ok = [a for a in algorithms if a["verdict"] == "ok"]

    if crit:
        verdict = "critical"
        message = f"Found {len(crit)} broken/deprecated primitive(s): {', '.join(a['algorithm'] for a in crit)}"
    elif warn:
        verdict = "warn"
        message = f"Found {len(warn)} weak/deprecated primitive(s): {', '.join(a['algorithm'] for a in warn)}"
    elif ok:
        verdict = "ok"
        message = f"Modern crypto detected: {', '.join(a['algorithm'] for a in ok[:6])}"
    else:
        verdict = "info"
        message = "No crypto primitives detected."

    return {"verdict": verdict, "message": message,
            "counts": {"critical": len(crit), "warn": len(warn), "ok": len(ok)}}


# ──────────────────────────────────────────────────────────────────────
# JSON-ready dict
# ──────────────────────────────────────────────────────────────────────

def to_dict(result: ScanResult,
             refined_hits: list[Hit],
             clusters: list[HeuristicHit],
             modified_sboxes: list[HeuristicHit],
             high_entropy: list[HeuristicHit]) -> dict:
    agg = aggregate(result, refined_hits)
    verdict = overall_verdict(agg["algorithms"])

    out = {
        "binary": result.binary_path,
        "format": result.format,
        "architecture": result.architecture,
        "file_size": result.file_size,
        "scan_seconds": result.scan_seconds,
        "verdict": verdict,
        "summary": {
            "total_hits": len(refined_hits),
            "algorithms_detected": len(agg["algorithms"]),
            "ecc_curves": [a["algorithm"] for a in agg["algorithms"] if a["family"] == "ecc"],
            "weak_or_broken": [a["algorithm"] for a in agg["algorithms"]
                                if a["verdict"] in ("critical", "warn") and a["family"] != "library-marker"],
        },
        "algorithms": agg["algorithms"],
        "hits": [h.to_dict() for h in refined_hits],
        "heuristics": {
            "aes_clusters": [c.to_dict() for c in clusters],
            "modified_sboxes": [m.to_dict() for m in modified_sboxes],
            "high_entropy_regions": [h.to_dict() for h in high_entropy],
        },
    }
    return out


# ──────────────────────────────────────────────────────────────────────
# Pretty terminal output
# ──────────────────────────────────────────────────────────────────────

def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


class _C:
    """Lazy color codes — empty strings when stdout isn't a TTY."""
    def __init__(self, on: bool) -> None:
        self.on = on
    def _w(self, code: str) -> str:
        return f"\033[{code}m" if self.on else ""
    @property
    def reset(self):  return self._w("0")
    @property
    def bold(self):   return self._w("1")
    @property
    def dim(self):    return self._w("2")
    @property
    def red(self):    return self._w("31")
    @property
    def green(self):  return self._w("32")
    @property
    def yellow(self): return self._w("33")
    @property
    def blue(self):   return self._w("34")
    @property
    def magenta(self):return self._w("35")
    @property
    def cyan(self):   return self._w("36")
    @property
    def gray(self):   return self._w("90")


def _verdict_color(c: _C, verdict: str) -> str:
    return {
        "critical": c.red,
        "warn":     c.yellow,
        "ok":       c.green,
        "info":     c.cyan,
        "suspicious": c.magenta,
    }.get(verdict, c.reset)


def _verdict_glyph(verdict: str) -> str:
    return {"critical": "[!]", "warn": "[~]", "ok": "[+]", "info": "[i]", "suspicious": "[?]"}.get(verdict, " ")


def render_text(d: dict, color: bool | None = None) -> str:
    """Human-readable terminal report."""
    c = _C(_supports_color() if color is None else color)
    lines: list[str] = []

    # Header
    lines.append(f"{c.bold}cryptid{c.reset} {c.dim}— cryptographic primitive scan{c.reset}")
    lines.append("")
    lines.append(f"  binary:  {c.cyan}{d['binary']}{c.reset}")
    lines.append(f"  format:  {d['format']} / {d['architecture']}    "
                 f"size: {d['file_size']:,} bytes    scan: {d['scan_seconds']}s")
    lines.append("")

    # Verdict
    v = d["verdict"]
    vc = _verdict_color(c, v["verdict"])
    glyph = _verdict_glyph(v["verdict"])
    lines.append(f"  {vc}{c.bold}{glyph} {v['verdict'].upper()}{c.reset}  {v['message']}")
    counts = v["counts"]
    if counts["critical"] or counts["warn"] or counts["ok"]:
        bar = []
        if counts["critical"]:
            bar.append(f"{c.red}{counts['critical']} critical{c.reset}")
        if counts["warn"]:
            bar.append(f"{c.yellow}{counts['warn']} warn{c.reset}")
        if counts["ok"]:
            bar.append(f"{c.green}{counts['ok']} ok{c.reset}")
        lines.append("  " + "   ".join(bar))
    lines.append("")

    # Algorithms
    if d["algorithms"]:
        lines.append(f"  {c.bold}detected primitives{c.reset}")
        # Group by family
        by_family = defaultdict(list)
        for a in d["algorithms"]:
            by_family[a["family"]].append(a)
        family_order = ["block-cipher", "stream-cipher", "hash", "ecc", "asymmetric",
                        "checksum", "library-marker", "unknown"]
        for fam in family_order:
            if fam not in by_family:
                continue
            lines.append(f"    {c.dim}# {fam}{c.reset}")
            for a in by_family[fam]:
                vc = _verdict_color(c, a["verdict"])
                gly = _verdict_glyph(a["verdict"])
                lines.append(f"      {vc}{gly}{c.reset} {c.bold}{a['algorithm']:14}{c.reset} "
                             f"{c.dim}({a['evidence_count']} hit{'s' if a['evidence_count']!=1 else ''}, "
                             f"conf {a['confidence']}){c.reset}  {a['rationale']}")
                # Show evidence
                ev_str = ", ".join(a["evidence_kinds"][:4])
                if len(a["evidence_kinds"]) > 4:
                    ev_str += f", … +{len(a['evidence_kinds'])-4} more"
                lines.append(f"        {c.dim}↳ {ev_str}{c.reset}")
                # Sample location
                if a["sample_locations"]:
                    loc = a["sample_locations"][0]
                    locstr = ""
                    if loc.get("section"):
                        locstr = f"{loc.get('segment','')}.{loc.get('section','')}"
                    if loc.get("virtual_address"):
                        locstr += f"  VA={loc['virtual_address']}"
                    if locstr:
                        lines.append(f"        {c.dim}↳ {locstr}{c.reset}")
        lines.append("")

    # Heuristics
    h = d["heuristics"]
    if h["aes_clusters"]:
        lines.append(f"  {c.bold}AES clusters{c.reset}  "
                     f"{c.dim}(co-located AES tables → strong AES signal){c.reset}")
        for cl in h["aes_clusters"][:5]:
            lines.append(f"    {c.green}[+]{c.reset} 0x{cl['file_offset']:x} ({cl['size']} bytes): "
                         f"{', '.join(cl['detail']['constants'])}")
        lines.append("")

    if h["modified_sboxes"]:
        lines.append(f"  {c.bold}{c.magenta}modified S-boxes — POTENTIAL ROLLED CRYPTO{c.reset}")
        for m in h["modified_sboxes"][:8]:
            lines.append(f"    {c.magenta}[?]{c.reset} 0x{m['file_offset']:x}  "
                         f"distance {m['detail']['hamming_distance']}/256 from {m['detail']['reference']}")
        lines.append("")

    if h["high_entropy_regions"]:
        lines.append(f"  {c.bold}high-entropy regions{c.reset}  "
                     f"{c.dim}(possible: tables, encrypted blobs, packed code){c.reset}")
        for r in h["high_entropy_regions"][:6]:
            lines.append(f"    {c.cyan}[i]{c.reset} 0x{r['file_offset']:x}  "
                         f"{r['size']:>7,}B  mean={r['detail']['mean_entropy']}  max={r['detail']['max_entropy']}")
        lines.append("")

    # Summary actionables
    weak = d["summary"]["weak_or_broken"]
    if weak:
        lines.append(f"  {c.bold}{c.red}action items{c.reset}")
        for algo in weak:
            info = algo_info(algo)
            lines.append(f"    {c.red}!{c.reset} {algo}: {info['reason']}")
        lines.append("")

    return "\n".join(lines)


def render_markdown(d: dict) -> str:
    """Markdown report — for PR comments, audit docs, etc."""
    lines = []
    lines.append(f"# cryptid scan — `{d['binary']}`")
    lines.append("")
    lines.append(f"- **Format:** {d['format']} / {d['architecture']}")
    lines.append(f"- **Size:** {d['file_size']:,} bytes")
    lines.append(f"- **Scan time:** {d['scan_seconds']}s")
    lines.append("")
    v = d["verdict"]
    icon = {"critical": "🔴", "warn": "🟡", "ok": "🟢", "info": "🔵"}.get(v["verdict"], "⚪")
    lines.append(f"## Verdict: {icon} **{v['verdict'].upper()}**")
    lines.append("")
    lines.append(f"> {v['message']}")
    lines.append("")

    if d["algorithms"]:
        lines.append("## Detected primitives")
        lines.append("")
        lines.append("| Algorithm | Family | Verdict | Confidence | Evidence | Rationale |")
        lines.append("|-----------|--------|---------|------------|----------|-----------|")
        for a in d["algorithms"]:
            ev = "; ".join(a["evidence_kinds"][:3])
            lines.append(f"| `{a['algorithm']}` | {a['family']} | "
                         f"**{a['verdict']}** | {a['confidence']} | "
                         f"{ev} | {a['rationale']} |")
        lines.append("")

    h = d["heuristics"]
    if h["modified_sboxes"]:
        lines.append("## ⚠️ Possible rolled crypto")
        for m in h["modified_sboxes"]:
            lines.append(f"- `0x{m['file_offset']:x}` — distance {m['detail']['hamming_distance']}/256 "
                         f"from {m['detail']['reference']}")
        lines.append("")

    if h["high_entropy_regions"]:
        lines.append("## High-entropy regions")
        lines.append("")
        for r in h["high_entropy_regions"][:10]:
            lines.append(f"- `0x{r['file_offset']:x}` — {r['size']:,}B, mean={r['detail']['mean_entropy']}, "
                         f"max={r['detail']['max_entropy']}")
        lines.append("")

    return "\n".join(lines)
