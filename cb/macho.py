"""Mach-O binary parser wrapping otool/codesign/nm with optional LIEF."""
from __future__ import annotations

import glob
import hashlib
import os
import platform
import plistlib
import re
import string
import subprocess
import struct
from typing import Any

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

_THIN_CACHE: dict[tuple[str, float, str], str] = {}


def is_fat_binary(path: str) -> bool:
    """Check if a file is a fat (universal) Mach-O binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        if len(magic) < 4:
            return False
        m = int.from_bytes(magic, "big")
        return m in (0xCAFEBABE, 0xBEBAFECA)
    except OSError:
        return False


def get_fat_architectures(path: str) -> list[str]:
    """Return list of architecture strings in a fat binary (e.g. ['arm64', 'x86_64'])."""
    try:
        r = subprocess.run(
            ["lipo", "-info", path],
            capture_output=True, text=True, timeout=30,
        )
        # Output format: "Architectures in the fat file: /path are: arm64 x86_64"
        # or: "Non-fat file: /path is architecture: arm64"
        out = r.stdout.strip()
        if "are:" in out:
            return out.split("are:")[-1].strip().split()
        if "is architecture:" in out:
            return [out.split("is architecture:")[-1].strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def thin_binary(path: str, arch: str | None = None) -> str:
    """Extract a single-arch slice from a fat binary, with caching.

    If *path* is not a fat binary, returns it unchanged.
    If *arch* is None, the native architecture is used.
    Cached results are stored at /tmp/cb_thin_<hash>.dylib and reused
    while the source file's mtime has not changed.
    """
    if not is_fat_binary(path):
        return path

    if arch is None:
        machine = platform.machine()
        arch = "arm64" if machine == "arm64" else "x86_64"

    mtime = os.path.getmtime(path)
    cache_key = (path, mtime, arch)

    cached = _THIN_CACHE.get(cache_key)
    if cached and os.path.exists(cached):
        return cached

    h = hashlib.sha256(f"{path}:{mtime}:{arch}".encode()).hexdigest()[:16]
    tmp_path = f"/tmp/cb_thin_{h}.dylib"

    if os.path.exists(tmp_path):
        _THIN_CACHE[cache_key] = tmp_path
        return tmp_path

    try:
        subprocess.run(
            ["lipo", "-thin", arch, path, "-output", tmp_path],
            capture_output=True, text=True, timeout=60,
        )
        if os.path.exists(tmp_path):
            _THIN_CACHE[cache_key] = tmp_path
            return tmp_path
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return path


def _run(cmd: list[str], timeout: int = 30) -> tuple[str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s"


def resolve_binary(path: str) -> str:
    """Resolve a path to an actual binary — handles .app bundles and .framework bundles."""
    if path.endswith(".app"):
        info_plist = os.path.join(path, "Contents", "Info.plist")
        if os.path.exists(info_plist):
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            exec_name = plist.get("CFBundleExecutable", "")
            if exec_name:
                resolved = os.path.join(path, "Contents", "MacOS", exec_name)
                if os.path.exists(resolved):
                    return resolved

    if path.endswith(".framework"):
        fw_name = os.path.basename(path).rsplit(".framework", 1)[0]

        # Try Versions/Current/Info.plist first, then root Info.plist
        for plist_rel in ("Versions/Current/Info.plist", "Info.plist"):
            info_plist = os.path.join(path, plist_rel)
            if os.path.exists(info_plist):
                try:
                    with open(info_plist, "rb") as f:
                        plist = plistlib.load(f)
                    exec_name = plist.get("CFBundleExecutable", "")
                    if exec_name:
                        plist_dir = os.path.dirname(info_plist)
                        resolved = os.path.join(plist_dir, exec_name)
                        if os.path.exists(resolved):
                            return resolved
                except Exception:
                    continue

        # Fallback: look for binary named after the framework (no plist)
        for candidate in (
            os.path.join(path, "Versions", "Current", fw_name),
            os.path.join(path, fw_name),
        ):
            if os.path.isfile(candidate):
                return candidate

    return path


def is_dyld_shared_cache(path: str) -> bool:
    """Check if a path is a dyld shared cache file."""
    basename = os.path.basename(path)
    return basename.startswith("dyld_shared_cache")


def extract_from_shared_cache(cache_path: str, library_name: str, output_dir: str | None = None) -> str | None:
    """Extract a library from the dyld shared cache.

    Tries multiple extraction methods:
    1. dyld_shared_cache_util (Xcode)
    2. ipsw (if installed)
    3. dsc_extractor (if available)
    """
    if output_dir is None:
        import tempfile
        output_dir = os.path.join(tempfile.gettempdir(), "cb_dsc_extract")
    os.makedirs(output_dir, exist_ok=True)

    # Method 1: dyld_shared_cache_util (ships with Xcode)
    for tool in ["dyld_shared_cache_util",
                 "/usr/bin/dyld_shared_cache_util"]:
        try:
            r = subprocess.run(
                [tool, "-extract", output_dir, cache_path],
                capture_output=True, text=True, timeout=120
            )
            # Find the extracted library
            matches = glob.glob(os.path.join(output_dir, "**", f"*{library_name}*"),
                                recursive=True)
            if matches:
                return matches[0]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # Method 2: ipsw dyld extract (if installed via brew)
    try:
        r = subprocess.run(
            ["ipsw", "dyld", "extract", cache_path, library_name,
             "--output", output_dir],
            capture_output=True, text=True, timeout=120
        )
        matches = glob.glob(os.path.join(output_dir, "**", f"*{library_name}*"),
                            recursive=True)
        if matches:
            return matches[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def list_shared_cache_images(cache_path: str) -> list[str]:
    """List libraries in a dyld shared cache."""
    # Try dyld_shared_cache_util
    try:
        r = subprocess.run(
            ["dyld_shared_cache_util", "-list", cache_path],
            capture_output=True, text=True, timeout=30
        )
        if r.stdout:
            return [line.strip() for line in r.stdout.splitlines()
                    if line.strip() and not line.startswith("dyld")]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: ipsw
    try:
        r = subprocess.run(
            ["ipsw", "dyld", "list", cache_path],
            capture_output=True, text=True, timeout=30
        )
        if r.stdout:
            return [line.strip() for line in r.stdout.splitlines()
                    if line.strip().startswith("/")]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return []


def detect_format(path: str) -> str:
    """Detect binary format from magic bytes."""
    with open(path, "rb") as f:
        magic = f.read(4)
    m = int.from_bytes(magic, "big")
    formats = {
        0xFEEDFACF: "macho64",
        0xFEEDFACE: "macho32",
        0xBEBAFECA: "fat",
        0xCAFEBABE: "fat",  # or Java class - check context
        0xCFFAEDFE: "macho64_le",
        0xCEFAEDFE: "macho32_le",
    }
    if magic[:4] == b"\x7fELF":
        return "elf"
    return formats.get(m, "unknown")


def get_file_info(path: str) -> dict[str, Any]:
    """Basic file info via file command."""
    resolved = resolve_binary(path)
    stdout, _ = _run(["file", "-b", resolved])
    size = os.path.getsize(resolved)
    fmt = detect_format(resolved)
    return {
        "path": path,
        "size_bytes": size,
        "size_human": _human_size(size),
        "format": fmt,
        "file_description": stdout.strip(),
    }


def get_architectures(path: str) -> list[dict[str, Any]]:
    """Get architecture info from Mach-O."""
    stdout, _ = _run(["otool", "-hv", path])
    archs = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Mach") or line.startswith("magic"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            arch_info = {
                "cputype": parts[0],
                "cpusubtype": parts[1],
                "caps": parts[2] if len(parts) > 2 else "",
                "filetype": parts[3] if len(parts) > 3 else "",
            }
            # Map common types
            ct = parts[0].upper()
            if "ARM64" in ct:
                arch_info["arch"] = "arm64"
                arch_info["bits"] = 64
            elif "X86_64" in ct:
                arch_info["arch"] = "x86_64"
                arch_info["bits"] = 64
            elif "I386" in ct or "X86" in ct:
                arch_info["arch"] = "x86"
                arch_info["bits"] = 32
            else:
                arch_info["arch"] = ct.lower()
                arch_info["bits"] = 64  # guess
            archs.append(arch_info)
    return archs


def get_protections(path: str) -> dict[str, Any]:
    """Get security protections for Mach-O binary."""
    result = {"pie": False, "code_signing": {}, "flags": []}

    # Header flags (PIE etc)
    stdout, _ = _run(["otool", "-hv", path])
    if "PIE" in stdout:
        result["pie"] = True
    # Extract flags from header
    flags_match = re.findall(r"(?:NOUNDEFS|DYLDLINK|TWOLEVEL|PIE|MH_\w+)", stdout)
    result["flags"] = list(set(flags_match))

    # Code signing
    _, stderr = _run(["codesign", "-dvvv", path])
    cs_out = stderr  # codesign outputs to stderr
    result["code_signing"]["signed"] = "Signature=" in cs_out
    result["code_signing"]["hardened_runtime"] = "runtime" in cs_out.lower()

    # Authority
    auth_match = re.search(r"Authority=(.+)", cs_out)
    if auth_match:
        result["code_signing"]["authority"] = auth_match.group(1).strip()

    team_match = re.search(r"TeamIdentifier=(.+)", cs_out)
    if team_match:
        result["code_signing"]["team_id"] = team_match.group(1).strip()

    # Entitlements
    ent_out, _ = _run(["codesign", "-d", "--entitlements", "-", path])
    ent_stderr_out, ent_stderr = _run(["codesign", "-d", "--entitlements", "-", path])
    # Count entitlement keys
    ent_count = len(re.findall(r"<key>", ent_out + ent_stderr))
    result["code_signing"]["entitlements_count"] = ent_count

    return result


def get_entitlements(path: str) -> dict[str, Any]:
    """Extract full entitlements dict with proper plist parsing."""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", "-", "--xml", path],
            capture_output=True, timeout=30
        )
        # codesign outputs entitlements XML to stderr with a preamble
        raw = result.stderr
        # Find the start of the XML plist
        xml_start = raw.find(b"<?xml")
        if xml_start == -1:
            # Try without XML declaration - look for plist tag
            xml_start = raw.find(b"<plist")
        if xml_start == -1:
            # Fallback: try the blob format (first 8 bytes are magic+length)
            blob_start = raw.find(b"<!DOCTYPE")
            if blob_start != -1:
                xml_start = blob_start
        if xml_start >= 0:
            xml_data = raw[xml_start:]
            return plistlib.loads(xml_data)
    except (plistlib.InvalidFileException, Exception):
        pass
    # Fallback: regex-based extraction
    stdout, stderr = _run(["codesign", "-d", "--entitlements", "-", path])
    combined = stdout + stderr
    entitlements = {}
    # Parse key-value pairs from XML-like output
    for m in re.finditer(
        r"<key>([^<]+)</key>\s*<(true|false|string|integer|array|dict)\s*/?>([^<]*)",
        combined, re.DOTALL
    ):
        key, vtype, val = m.group(1), m.group(2), m.group(3).strip()
        if vtype == "true":
            entitlements[key] = True
        elif vtype == "false":
            entitlements[key] = False
        elif vtype == "string":
            entitlements[key] = val
        elif vtype == "integer":
            entitlements[key] = int(val) if val else 0
        else:
            entitlements[key] = True  # arrays/dicts marked as present
    return entitlements


def get_load_commands(path: str) -> list[dict[str, Any]]:
    """Parse all Mach-O load commands for deep analysis."""
    stdout, _ = _run(["otool", "-l", path])
    commands = []
    current_cmd = None

    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Load command"):
            if current_cmd:
                commands.append(current_cmd)
            current_cmd = {"fields": {}}
        elif current_cmd and " " in line:
            parts = line.split(None, 1)
            if len(parts) == 2:
                current_cmd["fields"][parts[0]] = parts[1]
            elif len(parts) == 1 and parts[0].startswith("cmd"):
                current_cmd["cmd"] = parts[0]

    if current_cmd:
        commands.append(current_cmd)
    return commands


def get_objc_classes(path: str) -> list[str]:
    """Extract Objective-C class names from binary."""
    classes = set()

    # Method 1: nm for OBJC_CLASS symbols (works on non-cache binaries)
    try:
        stdout, _ = _run(["nm", "-m", path])
        for line in stdout.splitlines():
            m = re.search(r"_OBJC_CLASS_\$_(\S+)", line)
            if m:
                classes.add(m.group(1))
    except Exception:
        pass

    # Method 2: objdump --macho --objc-meta-data (most comprehensive)
    if not classes:
        try:
            stdout, _ = _run(["objdump", "--macho", "--objc-meta-data", path],
                             timeout=60)
            for line in stdout.splitlines():
                # Class definitions: "0x... _OBJC_CLASS_$_ClassName"
                m = re.search(r"_OBJC_CLASS_\$_(\S+)", line)
                if m:
                    classes.add(m.group(1))
                # Class name in metadata: "    name   0x... ClassName"
                # Only capture when line is indented and in class context
                m = re.match(r"^\s+name\s+0x[0-9a-f]+\s+(\S+)", line)
                if m:
                    name = m.group(1)
                    # Filter out method/protocol names (they contain colons or brackets)
                    if ":" not in name and "[" not in name and len(name) < 200:
                        classes.add(name)
        except Exception:
            pass

    # Method 3: LIEF (if available)
    if not classes and HAS_LIEF:
        try:
            binary = lief.parse(path)
            if binary and hasattr(binary, 'objc_metadata'):
                meta = binary.objc_metadata
                if meta:
                    for cls in meta.classes:
                        classes.add(cls.name)
        except Exception:
            pass

    return sorted(classes)


def get_objc_selectors(path: str) -> list[str]:
    """Extract Objective-C selectors from binary."""
    selectors = set()

    # Method 1: otool selrefs - most reliable for both x86_64 and arm64
    for seg in ["__DATA", "__DATA_CONST"]:
        try:
            stdout, _ = _run(["otool", "-v", "-s", seg, "__objc_selrefs", path])
            for line in stdout.splitlines():
                m = re.search(r"__TEXT:__objc_methname?:(\S+)", line)
                if m:
                    selectors.add(m.group(1))
        except Exception:
            pass

    # Method 2: objdump --macho --objc-meta-data for resolved method names
    # Only use if method 1 found nothing (objdump is slower)
    if not selectors:
        try:
            stdout, _ = _run(["objdump", "--macho", "--objc-meta-data", path],
                             timeout=60)
            in_methods = False
            for line in stdout.splitlines():
                if "baseMethods" in line or "baseMethodList" in line:
                    in_methods = True
                elif re.match(r"\s+base(Protocols|Properties|Ivars|ivars)", line):
                    in_methods = False
                if in_methods:
                    # Method name lines: "  name  0x... selectorName"
                    m = re.match(r"^\s+name\s+0x[0-9a-f]+\s+(\S+)", line)
                    if m:
                        name = m.group(1)
                        # Skip if it's a reference that extends past EOF
                        if "extends" not in name:
                            selectors.add(name)
                # Full method signatures: "-[Class selector]"
                m = re.search(r"[-+]\[(\S+)\s+([^\]]+)\]", line)
                if m:
                    selectors.add(m.group(2).strip())
        except Exception:
            pass

    # Method 3: nm for method name literals
    try:
        stdout, _ = _run(["nm", "-m", path])
        for line in stdout.splitlines():
            if "__objc_methname" in line:
                m = re.search(r"literal string: (.+)", line)
                if m:
                    selectors.add(m.group(1).strip())
    except Exception:
        pass

    return sorted(selectors)


def get_sections(path: str) -> list[dict[str, Any]]:
    """Get section info from load commands."""
    stdout, _ = _run(["otool", "-l", path])
    sections = []
    current_seg = ""
    in_section = False
    section = {}

    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("segname"):
            current_seg = line.split()[-1] if line.split() else ""
        elif line.startswith("Section"):
            if section:
                sections.append(section)
            section = {}
            in_section = True
        elif in_section:
            if line.startswith("sectname"):
                section["name"] = f"{current_seg}.{line.split()[-1]}"
            elif line.startswith("size"):
                try:
                    section["size"] = int(line.split()[-1], 16)
                except (ValueError, IndexError):
                    section["size"] = 0
            elif line.startswith("offset"):
                try:
                    section["offset"] = int(line.split()[-1])
                except (ValueError, IndexError):
                    pass

    if section:
        sections.append(section)

    return sections


def get_imports(path: str) -> list[str]:
    """Get imported symbols."""
    timeout = 120 if os.path.getsize(path) > 50_000_000 else 30
    stdout, _ = _run(["nm", "-u", path], timeout=timeout)
    imports = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            # nm -u output: "                 U _symbol"
            parts = line.split()
            if parts:
                sym = parts[-1]
                # Strip leading underscore (Mach-O convention)
                name = sym[1:] if sym.startswith("_") else sym
                imports.append(name)
    return imports


def get_exports(path: str) -> list[str]:
    """Get exported symbols."""
    timeout = 120 if os.path.getsize(path) > 50_000_000 else 30
    stdout, _ = _run(["nm", "-gU", path], timeout=timeout)
    exports = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            sym = parts[-1]
            name = sym[1:] if sym.startswith("_") else sym
            exports.append(name)
    return exports


def get_libraries(path: str) -> list[str]:
    """Get linked libraries."""
    stdout, _ = _run(["otool", "-L", path])
    libs = []
    for line in stdout.splitlines()[1:]:  # skip first line (binary name)
        line = line.strip()
        if line:
            lib = line.split("(")[0].strip()
            if lib:
                libs.append(lib)
    return libs


def _extract_strings_chunked(path: str, min_length: int, max_strings: int = 5000) -> list[str]:
    """Extract printable ASCII strings from a file by reading in 1MB chunks.

    Used for large binaries where the external ``strings`` command may hang.
    """
    printable = set(string.printable.encode("ascii")) - {0x0B, 0x0C}  # exclude VT/FF
    results: list[str] = []
    buf = bytearray()
    chunk_size = 1 << 20  # 1 MB

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            for byte in chunk:
                if byte in printable:
                    buf.append(byte)
                else:
                    if len(buf) >= min_length:
                        results.append(buf.decode("ascii", errors="replace"))
                        if len(results) >= max_strings:
                            return results
                    buf.clear()
        # flush remaining buffer
        if len(buf) >= min_length:
            results.append(buf.decode("ascii", errors="replace"))
    return results


def get_strings(path: str, min_length: int = 6, max_count: int = 100) -> dict[str, Any]:
    """Get strings from binary, categorized."""
    file_size = os.path.getsize(path)
    if file_size > 100_000_000:
        # Large binary: use Python-native extraction to avoid strings(1) hanging
        all_strings = _extract_strings_chunked(path, min_length, max_strings=5000)
    else:
        stdout, _ = _run(["strings", "-n", str(min_length), path], timeout=60)
        all_strings = stdout.splitlines()[:5000]  # cap raw input

    categories = {
        "urls": [],
        "file_paths": [],
        "format_strings": [],
        "error_messages": [],
        "crypto_related": [],
        "debug_info": [],
        "interesting": [],
    }

    url_re = re.compile(r"https?://")
    path_re = re.compile(r"^/[a-zA-Z]")
    fmt_re = re.compile(r"%[0-9]*[sdxXnplfFeEgG]")
    err_re = re.compile(r"(error|fail|invalid|denied|refused|abort|corrupt|overflow)",
                        re.IGNORECASE)
    crypto_re = re.compile(r"(AES|RSA|SHA|HMAC|crypt|cipher|key|cert|ssl|tls)",
                           re.IGNORECASE)

    for s in all_strings:
        s = s.strip()
        if not s:
            continue
        if url_re.search(s):
            categories["urls"].append(s)
        elif path_re.match(s):
            categories["file_paths"].append(s)
        elif fmt_re.search(s):
            categories["format_strings"].append(s)
        elif err_re.search(s):
            categories["error_messages"].append(s)
        elif crypto_re.search(s):
            categories["crypto_related"].append(s)

    # Trim each category
    per_cat = max(max_count // 6, 5)
    for k in categories:
        categories[k] = categories[k][:per_cat]

    return {
        "total_strings": len(all_strings),
        "categories": categories,
    }


def _human_size(nbytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"


def get_section_data(path: str, segment: str, section: str) -> bytes | None:
    """Extract raw data from a Mach-O section.

    Args:
        path: Binary path
        segment: Segment name (e.g. '__TEXT')
        section: Section name (e.g. '__sandbox_profile')

    Returns:
        bytes or None
    """
    # Try LIEF first (more reliable)
    if HAS_LIEF:
        try:
            binary = lief.parse(path)
            if binary:
                sec = binary.get_section(section)
                if sec:
                    return bytes(sec.content)
        except Exception:
            pass

    # Fallback: otool -s
    stdout, _ = _run(["otool", "-s", segment, section, "-V", path])
    if stdout and "Contents of" in stdout:
        # Parse hex dump
        hex_bytes = []
        for line in stdout.splitlines():
            # Skip header lines
            if line.startswith("Contents") or line.strip().startswith(path):
                continue
            # Parse hex: "0000addr  xx xx xx xx ..."
            parts = line.strip().split()
            if len(parts) > 1:
                for p in parts[1:]:
                    if len(p) == 2:
                        try:
                            hex_bytes.append(int(p, 16))
                        except ValueError:
                            continue
                    elif len(p) == 8:
                        # otool sometimes outputs 32-bit words
                        try:
                            word = int(p, 16)
                            hex_bytes.extend(word.to_bytes(4, "big"))
                        except ValueError:
                            continue
        if hex_bytes:
            return bytes(hex_bytes)
    return None


def get_embedded_sandbox_profile(path: str) -> str | None:
    """Extract embedded sandbox profile from __TEXT,__sandbox_profile section."""
    data = get_section_data(path, "__TEXT", "__sandbox_profile")
    if data:
        try:
            # Strip null terminator if present
            if data.endswith(b"\x00"):
                data = data.rstrip(b"\x00")
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    return None
