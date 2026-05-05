"""Binary scanner — finds crypto fingerprints in compiled binaries.

Strategy: memory-map the file and run substring search for every fingerprint
across the whole image. For Mach-O/ELF/PE we also resolve each hit to the
containing section + virtual address.

Why memmap + str.find loops instead of Aho-Corasick? With ~50 patterns and
typical binaries under 200MB, Python's underlying memmem (Boyer-Moore-Horspool)
gets us well under a second on a release build of openssl. Adding AC would be
an unjustified dependency.
"""
from __future__ import annotations

import mmap
import os
from dataclasses import dataclass, field
from typing import Iterable

from cb.crypto.constants import CRYPTO_FINGERPRINTS, Fingerprint


@dataclass
class Hit:
    fingerprint: Fingerprint
    file_offset: int
    virtual_address: int | None = None
    segment: str | None = None
    section: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.fingerprint.name,
            "algorithm": self.fingerprint.algorithm,
            "category": self.fingerprint.category,
            "endian": self.fingerprint.endian,
            "severity": self.fingerprint.severity,
            "confidence": self.fingerprint.confidence,
            "notes": self.fingerprint.notes,
            "file_offset": self.file_offset,
            "virtual_address": (
                f"0x{self.virtual_address:x}" if self.virtual_address is not None else None
            ),
            "segment": self.segment,
            "section": self.section,
            "match_size": len(self.fingerprint.bytes),
        }


@dataclass
class SectionInfo:
    name: str
    segment: str
    file_offset: int
    file_size: int
    virtual_address: int


@dataclass
class ScanResult:
    binary_path: str | None
    file_size: int
    hits: list[Hit] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    format: str = "unknown"
    architecture: str = "unknown"
    scanned_bytes: int = 0
    scan_seconds: float = 0.0


# ──────────────────────────────────────────────────────────────────────
# Section discovery (LIEF-backed, with graceful fallback)
# ──────────────────────────────────────────────────────────────────────

def _discover_sections(path: str) -> tuple[list[SectionInfo], str, str]:
    """Return sections, format, architecture using LIEF.

    Falls back to a single 'whole-file' section if LIEF can't parse the file.
    """
    sections: list[SectionInfo] = []
    fmt = "raw"
    arch = "unknown"
    try:
        import lief  # type: ignore
        binary = lief.parse(path)
        if binary is None:
            return sections, fmt, arch

        # LIEF subclasses are all named "Binary" — distinguish by module path.
        module = type(binary).__module__  # e.g. "lief._lief.MachO"
        is_macho = "MachO" in module
        is_elf = "ELF" in module
        is_pe = "PE" in module

        # FatBinary on Mach-O: the parsed object is a FatBinary, walk to first slice
        if is_macho and hasattr(binary, "at") and not hasattr(binary, "sections"):
            try:
                if binary.size > 0:
                    binary = binary.at(0)
            except Exception:
                pass

        if is_macho:
            fmt = "macho"
            try:
                arch = str(binary.header.cpu_type).split(".")[-1].lower()
            except Exception:
                pass
            for s in binary.sections:
                seg = ""
                try:
                    if hasattr(s, "segment_name") and s.segment_name:
                        seg = s.segment_name
                    elif hasattr(s, "segment") and s.segment:
                        seg = s.segment.name
                except Exception:
                    seg = ""
                sections.append(SectionInfo(
                    name=s.name,
                    segment=seg or "?",
                    file_offset=int(getattr(s, "offset", 0) or 0),
                    file_size=int(getattr(s, "size", 0) or 0),
                    virtual_address=int(getattr(s, "virtual_address", 0) or 0),
                ))
        elif is_elf:
            fmt = "elf"
            try:
                arch = str(binary.header.machine_type).split(".")[-1].lower()
            except Exception:
                pass
            for s in binary.sections:
                sections.append(SectionInfo(
                    name=s.name or "",
                    segment="",
                    file_offset=int(getattr(s, "file_offset", 0) or
                                    getattr(s, "offset", 0) or 0),
                    file_size=int(getattr(s, "size", 0) or 0),
                    virtual_address=int(getattr(s, "virtual_address", 0) or 0),
                ))
        elif is_pe:
            fmt = "pe"
            try:
                arch = str(binary.header.machine).split(".")[-1].lower()
            except Exception:
                pass
            image_base = int(getattr(binary.optional_header, "imagebase", 0) or 0)
            for s in binary.sections:
                sections.append(SectionInfo(
                    name=s.name or "",
                    segment="",
                    file_offset=int(s.pointerto_raw_data or 0),
                    file_size=int(s.sizeof_raw_data or 0),
                    virtual_address=image_base + int(s.virtual_address or 0),
                ))
    except ImportError:
        pass
    except Exception:
        pass
    return sections, fmt, arch


def _locate_offset(offset: int, sections: list[SectionInfo]) -> SectionInfo | None:
    """Find the section containing a given file offset. O(n) — sections are few."""
    for s in sections:
        if s.file_size <= 0:
            continue
        if s.file_offset <= offset < s.file_offset + s.file_size:
            return s
    return None


# ──────────────────────────────────────────────────────────────────────
# Search
# ──────────────────────────────────────────────────────────────────────

def _search_pattern(haystack: mmap.mmap | bytes, needle: bytes, max_hits: int = 32) -> list[int]:
    """Return file offsets of all occurrences of `needle`. Capped at max_hits."""
    if not needle or len(needle) > len(haystack):
        return []
    out: list[int] = []
    start = 0
    while len(out) < max_hits:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        out.append(idx)
        start = idx + 1  # allow overlapping matches; matters for marker strings
    return out


def scan_bytes(data: bytes, fingerprints: Iterable[Fingerprint] | None = None,
               max_hits_per_pattern: int = 32) -> list[Hit]:
    """Scan a raw bytes buffer for crypto fingerprints. Returns Hits with no
    section context (file_offset only).
    """
    fps = list(fingerprints) if fingerprints is not None else CRYPTO_FINGERPRINTS
    hits: list[Hit] = []
    for fp in fps:
        for off in _search_pattern(data, fp.bytes, max_hits_per_pattern):
            hits.append(Hit(fingerprint=fp, file_offset=off))
    return hits


def scan_binary(path: str, fingerprints: Iterable[Fingerprint] | None = None,
                max_hits_per_pattern: int = 32) -> ScanResult:
    """Scan a file on disk for crypto fingerprints, resolving section context."""
    import time
    t0 = time.time()

    fps = list(fingerprints) if fingerprints is not None else CRYPTO_FINGERPRINTS
    file_size = os.path.getsize(path)

    sections, fmt, arch = _discover_sections(path)
    result = ScanResult(
        binary_path=path,
        file_size=file_size,
        sections=sections,
        format=fmt,
        architecture=arch,
    )

    if file_size == 0:
        result.scan_seconds = round(time.time() - t0, 3)
        return result

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            result.scanned_bytes = file_size
            for fp in fps:
                if len(fp.bytes) > file_size:
                    continue
                offsets = _search_pattern(mm, fp.bytes, max_hits_per_pattern)
                for off in offsets:
                    sec = _locate_offset(off, sections)
                    va = None
                    seg = None
                    sname = None
                    if sec:
                        va = sec.virtual_address + (off - sec.file_offset)
                        seg = sec.segment
                        sname = sec.name
                    result.hits.append(Hit(
                        fingerprint=fp,
                        file_offset=off,
                        virtual_address=va,
                        segment=seg,
                        section=sname,
                    ))

    result.scan_seconds = round(time.time() - t0, 3)
    return result
