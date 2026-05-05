"""Diff two binaries' crypto profiles.

Useful for:
  - Tracking malware variants (did the new sample swap chacha20 for AES?)
  - Supply-chain regression checks (did this build downgrade a hash?)
  - Verifying crypto migrations (did we successfully replace MD5 with SHA-256?)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CryptoDiff:
    fingerprint_old: str
    fingerprint_new: str
    fingerprint_changed: bool
    added: list[dict]        # algorithms in new but not old
    removed: list[dict]      # algorithms in old but not new
    common: list[dict]       # algorithms in both
    severity_changes: list[dict]  # algorithms whose verdict differs

    def to_dict(self) -> dict:
        return {
            "fingerprint_old": self.fingerprint_old,
            "fingerprint_new": self.fingerprint_new,
            "fingerprint_changed": self.fingerprint_changed,
            "added": self.added,
            "removed": self.removed,
            "common": self.common,
            "severity_changes": self.severity_changes,
        }


def diff_reports(old: dict, new: dict) -> CryptoDiff:
    """Compute the set difference between two crypto reports."""
    old_algos = {a["algorithm"]: a for a in old.get("algorithms", [])}
    new_algos = {a["algorithm"]: a for a in new.get("algorithms", [])}

    added_keys = sorted(new_algos.keys() - old_algos.keys())
    removed_keys = sorted(old_algos.keys() - new_algos.keys())
    common_keys = sorted(old_algos.keys() & new_algos.keys())

    severity_changes = []
    for k in common_keys:
        if old_algos[k]["verdict"] != new_algos[k]["verdict"]:
            severity_changes.append({
                "algorithm": k,
                "old_verdict": old_algos[k]["verdict"],
                "new_verdict": new_algos[k]["verdict"],
            })

    return CryptoDiff(
        fingerprint_old=old.get("fingerprint", ""),
        fingerprint_new=new.get("fingerprint", ""),
        fingerprint_changed=old.get("fingerprint", "") != new.get("fingerprint", ""),
        added=[{"algorithm": k, **new_algos[k]} for k in added_keys],
        removed=[{"algorithm": k, **old_algos[k]} for k in removed_keys],
        common=[{"algorithm": k, "verdict": new_algos[k]["verdict"]} for k in common_keys],
        severity_changes=severity_changes,
    )


def render_diff_text(diff: CryptoDiff, old_path: str, new_path: str,
                      color: bool = False) -> str:
    """Pretty terminal diff."""
    def C(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    lines = []
    lines.append(C("1", "cryptid diff") + " " + C("2", "— crypto profile delta"))
    lines.append("")
    lines.append(f"  old: {C('36', old_path)}")
    lines.append(f"  new: {C('36', new_path)}")
    lines.append("")
    fp_old = diff.fingerprint_old or "(none)"
    fp_new = diff.fingerprint_new or "(none)"
    if diff.fingerprint_changed:
        lines.append(f"  fingerprint: {C('31', fp_old)} → {C('32', fp_new)}  "
                     f"{C('1;33', '(CHANGED)')}")
    else:
        lines.append(f"  fingerprint: {C('32', fp_old)}  "
                     f"{C('2', '(unchanged)')}")
    lines.append("")

    if not diff.added and not diff.removed and not diff.severity_changes:
        lines.append(C("32", "  [+] No crypto changes."))
        return "\n".join(lines)

    if diff.added:
        lines.append(C("1", "  added"))
        for a in diff.added:
            v = a.get("verdict", "info")
            ic = {"critical": "31", "warn": "33", "ok": "32", "info": "36"}.get(v, "0")
            lines.append(f"    {C(ic, '+')}  {a['algorithm']:14} "
                         f"{C('2', f'({v})')}  {a.get('rationale', '')}")
        lines.append("")

    if diff.removed:
        lines.append(C("1", "  removed"))
        for a in diff.removed:
            v = a.get("verdict", "info")
            ic = {"critical": "31", "warn": "33", "ok": "32", "info": "36"}.get(v, "0")
            lines.append(f"    {C('31', '-')}  {a['algorithm']:14} "
                         f"{C('2', f'(was {v})')}")
        lines.append("")

    if diff.severity_changes:
        lines.append(C("1", "  severity changes"))
        for s in diff.severity_changes:
            old_c = {"critical": "31", "warn": "33", "ok": "32"}.get(s["old_verdict"], "0")
            new_c = {"critical": "31", "warn": "33", "ok": "32"}.get(s["new_verdict"], "0")
            lines.append(f"    *  {s['algorithm']:14}  "
                         f"{C(old_c, s['old_verdict'])} → {C(new_c, s['new_verdict'])}")
        lines.append("")

    # Verdict
    if any(a.get("verdict") in ("critical", "warn") for a in diff.added):
        lines.append(C("1;31", "  ! New weak/broken crypto introduced"))
    elif any(s["new_verdict"] in ("critical", "warn") and
              s["old_verdict"] not in ("critical", "warn")
              for s in diff.severity_changes):
        lines.append(C("1;31", "  ! Crypto verdict regressed"))
    elif diff.removed and not diff.added:
        lines.append(C("32", "  [+] Crypto profile narrowed."))

    return "\n".join(lines)
