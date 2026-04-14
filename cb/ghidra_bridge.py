"""Ghidra headless analyzer bridge - orchestrates analyzeHeadless with Java scripts."""
import hashlib
import json
import os
import subprocess
import sys

from cb.config import get_ghidra_home, load_config

SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "ghidra_scripts")
JSON_START = "###CB_JSON_START###"
JSON_END = "###CB_JSON_END###"


class GhidraError(Exception):
    pass


def is_available():
    """Check if Ghidra is configured and available."""
    try:
        ghidra_home = get_ghidra_home()
        if not ghidra_home:
            return False
        headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
        return os.path.exists(headless)
    except Exception:
        return False


def _project_name(binary_path):
    """Generate project name from binary path hash."""
    h = hashlib.md5(os.path.abspath(binary_path).encode()).hexdigest()[:12]
    name = os.path.basename(binary_path).replace(" ", "_").replace(".", "_")
    return f"cb_{name}_{h}"


def _get_headless():
    """Find analyzeHeadless script."""
    ghidra_home = get_ghidra_home()
    if not ghidra_home:
        raise GhidraError(
            "Ghidra not found. Install with 'brew install --cask ghidra' "
            "or run 'cb ghidra setup --ghidra-home /path/to/ghidra'"
        )
    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if not os.path.exists(headless):
        raise GhidraError(f"analyzeHeadless not found at {headless}")
    return headless


def _project_dir():
    cfg = load_config()
    d = os.path.expanduser(cfg.get("ghidra_project_dir",
                                    "~/.cb/ghidra_projects"))
    os.makedirs(d, exist_ok=True)
    return d


def project_exists(binary_path):
    """Check if a Ghidra project already exists for this binary."""
    pdir = _project_dir()
    pname = _project_name(binary_path)
    # Ghidra creates .gpr and .rep files/dirs
    return os.path.exists(os.path.join(pdir, f"{pname}.gpr"))


def analyze(binary_path, timeout=600, force=False):
    """Import and analyze a binary. Returns project info."""
    headless = _get_headless()
    pdir = _project_dir()
    pname = _project_name(binary_path)

    if project_exists(binary_path) and not force:
        return {
            "status": "already_analyzed",
            "project_dir": pdir,
            "project_name": pname,
        }

    cmd = [
        headless, pdir, pname,
        "-import", os.path.abspath(binary_path),
        "-overwrite",
        "-analysisTimeoutPerFile", str(timeout),
    ]

    print(f"[*] Importing {binary_path} into Ghidra (this may take a while)...",
          file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 60
        )
    except subprocess.TimeoutExpired:
        raise GhidraError(f"Analysis timed out after {timeout}s")

    if result.returncode != 0 and "REPORT:" not in result.stdout:
        raise GhidraError(
            f"Ghidra analysis failed (rc={result.returncode}).\n"
            f"Stderr: {result.stderr[-500:]}"
        )

    return {
        "status": "analyzed",
        "project_dir": pdir,
        "project_name": pname,
    }


def run_ghidra_script(binary_path, script_name, script_args=None, timeout=300):
    """Run a Ghidra postScript and return parsed JSON output."""
    headless = _get_headless()
    pdir = _project_dir()
    pname = _project_name(binary_path)

    # Use -process if project exists, otherwise -import
    if project_exists(binary_path):
        cmd = [
            headless, pdir, pname,
            "-process", os.path.basename(binary_path),
            "-noanalysis",  # skip re-analysis
            "-scriptPath", SCRIPT_DIR,
            "-postScript", script_name,
        ]
    else:
        cmd = [
            headless, pdir, pname,
            "-import", os.path.abspath(binary_path),
            "-overwrite",
            "-scriptPath", SCRIPT_DIR,
            "-postScript", script_name,
        ]

    if script_args:
        cmd.extend(script_args)

    print(f"[*] Running Ghidra script: {script_name}", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise GhidraError(f"Ghidra script timed out after {timeout}s")

    # Parse JSON output delimited by markers
    output = result.stdout
    start = output.find(JSON_START)
    end = output.find(JSON_END)

    if start != -1 and end != -1:
        json_str = output[start + len(JSON_START):end].strip()
        # Ghidra's println prefixes lines with INFO logger text; strip it
        import re
        json_str = re.sub(r'^.*?(\{)', r'\1', json_str, count=1, flags=re.DOTALL)
        # Also strip any INFO prefixes on continuation lines
        json_str = re.sub(r'\n\s*\(GhidraScript\)\s*\n\s*INFO\s+\S+>\s*', '', json_str)
        # Strip trailing content after JSON end marker prefix
        json_str = re.sub(r'\}\s*\(GhidraScript\).*$', '}', json_str, flags=re.DOTALL)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise GhidraError(f"Invalid JSON from script: {e}\nRaw: {json_str[:200]}")

    # If no JSON markers, try to extract useful info from stdout
    if result.returncode != 0:
        raise GhidraError(
            f"Script failed (rc={result.returncode}).\n"
            f"Stdout (last 500): {result.stdout[-500:]}\n"
            f"Stderr (last 500): {result.stderr[-500:]}"
        )

    raise GhidraError(
        f"Script {script_name} produced no JSON output.\n"
        f"Stdout (last 500): {result.stdout[-500:]}"
    )
