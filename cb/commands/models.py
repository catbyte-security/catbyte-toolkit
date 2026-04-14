"""cb models - ML model file permission and integrity audit."""
import argparse
import hashlib
import os
import stat

from cb.output import add_output_args, make_formatter


# Model file extensions and their format descriptions
MODEL_EXTENSIONS = {
    ".tflite": "TensorFlow Lite",
    ".onnx": "ONNX",
    ".mlmodel": "Core ML",
    ".bin": "Binary weights (generic)",
    ".pb": "Protocol Buffer / TensorFlow SavedModel",
    ".safetensors": "SafeTensors (HuggingFace)",
}

# Directory name patterns that indicate security-sensitive model purposes
SENSITIVE_MODEL_INDICATORS = {
    "safe_browsing": {"risk": "high", "purpose": "Safe Browsing classification"},
    "phishing": {"risk": "high", "purpose": "Phishing detection"},
    "permission": {"risk": "high", "purpose": "Permission decision model"},
    "safety": {"risk": "high", "purpose": "Safety/content filtering"},
    "malware": {"risk": "high", "purpose": "Malware detection"},
    "client_side_detection": {"risk": "high", "purpose": "Client-side threat detection"},
    "optimization_guide": {"risk": "medium", "purpose": "Chrome optimization guide"},
    "segmentation": {"risk": "low", "purpose": "Image segmentation"},
    "translate": {"risk": "low", "purpose": "Translation model"},
    "autofill": {"risk": "medium", "purpose": "Autofill prediction"},
    "smart_reply": {"risk": "low", "purpose": "Smart reply suggestions"},
}


def register(subparsers):
    p = subparsers.add_parser("models", help="Audit ML model file permissions and integrity")
    p.add_argument("path", help="Directory to scan for model files")
    p.add_argument("--check-hashes", action="store_true",
                   help="Compute SHA256 hashes of model files")
    p.add_argument("--writable-only", action="store_true",
                   help="Only show user-writable model files")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    fmt = make_formatter(args)
    scan_path = os.path.expanduser(args.path)

    if not os.path.isdir(scan_path):
        fmt.emit({"error": f"Not a directory: {scan_path}"}, "models")
        return

    fmt.status(f"Scanning for ML model files: {scan_path}")
    model_files = _find_model_files(scan_path)
    fmt.status(f"Found {len(model_files)} model file(s)")

    if not model_files:
        fmt.emit({
            "scan_path": scan_path,
            "total_models": 0,
            "models": [],
            "findings": [],
        }, "models")
        return

    # Analyze each model
    models = []
    findings = []
    finding_id = 0

    for mf in model_files:
        analysis = _analyze_model(mf, check_hash=getattr(args, 'check_hashes', False))

        # Filter if --writable-only
        if getattr(args, 'writable_only', False) and not analysis.get("user_writable"):
            continue

        models.append(analysis)

        # Generate findings
        if analysis.get("user_writable"):
            finding_id += 1
            severity = "low"
            purpose_info = analysis.get("purpose_info")
            if purpose_info and purpose_info.get("risk") in ("high", "medium"):
                severity = purpose_info["risk"]

            finding = {
                "id": f"MODEL-{finding_id:03d}",
                "severity": severity,
                "file": analysis["relative_path"],
                "issue": "User-writable model file",
                "detail": f"Model file is writable by current user "
                          f"(permissions: {analysis.get('permissions', 'unknown')})",
            }
            if purpose_info:
                finding["purpose"] = purpose_info.get("purpose", "unknown")
                if purpose_info.get("risk") == "high":
                    finding["detail"] += (
                        f". This is a SECURITY-SENSITIVE model ({purpose_info['purpose']}). "
                        "A local attacker could replace the model to bypass "
                        f"{purpose_info['purpose'].lower()} protections."
                    )
            findings.append(finding)

    # Summary
    writable_count = sum(1 for m in models if m.get("user_writable"))
    sensitive_writable = sum(
        1 for m in models
        if m.get("user_writable") and m.get("purpose_info", {}).get("risk") == "high"
    )

    result = {
        "scan_path": scan_path,
        "total_models": len(models),
        "models": models[:getattr(args, 'max_results', 50)],
        "findings": findings,
        "summary": {
            "total_files": len(models),
            "user_writable": writable_count,
            "sensitive_writable": sensitive_writable,
            "risk_level": "high" if sensitive_writable > 0
                          else "medium" if writable_count > 0
                          else "low",
        },
    }

    fmt.emit(result, "models")


def _find_model_files(scan_path):
    """Recursively find model files by extension."""
    model_files = []
    for root, _dirs, files in os.walk(scan_path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in MODEL_EXTENSIONS:
                full_path = os.path.join(root, fname)
                model_files.append(full_path)
    return model_files


def _analyze_model(path, check_hash=False):
    """Analyze a single model file for permissions and purpose."""
    result = {
        "path": path,
        "relative_path": os.path.basename(path),
        "filename": os.path.basename(path),
    }

    # File info
    ext = os.path.splitext(path)[1].lower()
    result["format"] = MODEL_EXTENSIONS.get(ext, "unknown")

    try:
        st = os.stat(path)
        result["size_bytes"] = st.st_size
        result["permissions"] = oct(st.st_mode & 0o777)
        result["user_writable"] = os.access(path, os.W_OK)
        result["owner_uid"] = st.st_uid
    except OSError:
        result["size_bytes"] = 0
        result["permissions"] = "unknown"
        result["user_writable"] = False

    # Infer purpose from parent directory names
    parent_path = os.path.dirname(path).lower()
    result["purpose_info"] = None
    for indicator, info in SENSITIVE_MODEL_INDICATORS.items():
        if indicator in parent_path:
            result["purpose_info"] = info
            break

    # Optional hash
    if check_hash:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            result["sha256"] = h.hexdigest()
        except OSError:
            result["sha256"] = "error"

    return result


def main():
    parser = argparse.ArgumentParser(prog="cbmodels", description="ML model audit")
    parser.add_argument("path", help="Directory to scan for model files")
    parser.add_argument("--check-hashes", action="store_true")
    parser.add_argument("--writable-only", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
