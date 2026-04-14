"""Configuration management for cb toolkit."""
from __future__ import annotations

import json
import os
from typing import Any

CONFIG_PATH = os.path.expanduser("~/.cbconfig.json")
DEFAULT_CONFIG: dict[str, Any] = {
    "ghidra_home": "",
    "ghidra_project_dir": os.path.expanduser("~/.cb/ghidra_projects"),
    "lldb_python": "",
    "lldb_pythonpath": "",
    "default_arch": "auto",
    "default_format": "json",
    "default_max_results": 50,
    "dsc_extract_dir": os.path.expanduser("~/.cb/dsc_extract"),
    "verbose": False,
    "cache_dir": os.path.expanduser("~/.cb/cache/results"),
    "cache_enabled": True,
    "context_budget": 0,
    "plugin_dir": os.path.expanduser("~/.cb/plugins"),
    "session_dir": os.path.expanduser("~/.cb/sessions"),
    "db_path": os.path.expanduser("~/.cb/analysis.db"),
    "db_enabled": True,
}


def load_config() -> dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        merged = {**DEFAULT_CONFIG, **cfg}
        return merged
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def get_ghidra_home() -> str:
    cfg = load_config()
    home = cfg.get("ghidra_home", "")
    if home and os.path.isdir(home):
        return home
    # Auto-detect common locations
    candidates = [
        "/Applications/ghidra",
        "/Applications/Ghidra",
        os.path.expanduser("~/ghidra"),
        "/opt/homebrew/Caskroom/ghidra",
    ]
    for c in candidates:
        if os.path.isdir(c):
            # Find the actual versioned dir inside cask
            if "Caskroom" in c:
                for ver in sorted(os.listdir(c), reverse=True):
                    vpath = os.path.join(c, ver)
                    for item in os.listdir(vpath):
                        if item.startswith("ghidra_"):
                            found = os.path.join(vpath, item)
                            cfg["ghidra_home"] = found
                            save_config(cfg)
                            return found
            else:
                cfg["ghidra_home"] = c
                save_config(cfg)
                return c
    return ""
