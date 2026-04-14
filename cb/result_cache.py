"""Analysis result caching for cb toolkit."""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any


class ResultCache:
    def __init__(self, cache_dir: str | None = None) -> None:
        if cache_dir is None:
            from cb.config import load_config
            cfg = load_config()
            cache_dir = cfg.get("cache_dir",
                                os.path.expanduser("~/.cb/cache/results"))
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    def _file_identity(self, path: str) -> dict[str, Any]:
        """Get identity info for a binary file."""
        stat = os.stat(path)
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return {
            "sha256": sha.hexdigest(),
            "mtime": stat.st_mtime,
            "size": stat.st_size,
        }

    def _cache_path(self, sha256: str, command: str, args_hash: str) -> str:
        prefix = sha256[:2]
        return os.path.join(self.cache_dir, prefix, sha256,
                            f"{command}_{args_hash}.json")

    def _args_hash(self, args_dict: dict[str, Any]) -> str:
        canonical = json.dumps(args_dict, sort_keys=True, default=str)
        return hashlib.md5(canonical.encode()).hexdigest()[:12]

    def get(self, binary_path: str, command: str,
            args_dict: dict[str, Any]) -> dict[str, Any] | None:
        """Retrieve cached result, or None if miss/stale."""
        try:
            identity = self._file_identity(binary_path)
        except (OSError, IOError):
            return None

        sha256 = identity["sha256"]
        args_h = self._args_hash(args_dict)
        path = self._cache_path(sha256, command, args_h)

        if not os.path.exists(path):
            return None

        try:
            with open(path) as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

        stored = entry.get("_identity", {})
        if (stored.get("mtime") != identity["mtime"] or
                stored.get("size") != identity["size"]):
            # Stale — binary changed
            try:
                os.remove(path)
            except OSError:
                pass
            return None

        return entry.get("data")

    def put(self, binary_path: str, command: str,
            args_dict: dict[str, Any], data: dict[str, Any]) -> None:
        """Store result in cache."""
        try:
            identity = self._file_identity(binary_path)
        except (OSError, IOError):
            return

        sha256 = identity["sha256"]
        args_h = self._args_hash(args_dict)
        path = self._cache_path(sha256, command, args_h)

        os.makedirs(os.path.dirname(path), exist_ok=True)
        entry = {
            "_identity": identity,
            "_command": command,
            "_args": args_dict,
            "_cached_at": time.time(),
            "data": data,
        }
        with open(path, "w") as f:
            json.dump(entry, f, indent=2, default=str)

    def clear(self, binary_path: str | None = None) -> int:
        """Remove cache entries. Returns count of removed files."""
        count = 0
        if binary_path:
            try:
                identity = self._file_identity(binary_path)
                sha256 = identity["sha256"]
                prefix = sha256[:2]
                target_dir = os.path.join(self.cache_dir, prefix, sha256)
                if os.path.isdir(target_dir):
                    for f in os.listdir(target_dir):
                        os.remove(os.path.join(target_dir, f))
                        count += 1
                    os.rmdir(target_dir)
            except (OSError, IOError):
                pass
        else:
            for root, dirs, files in os.walk(self.cache_dir, topdown=False):
                for f in files:
                    os.remove(os.path.join(root, f))
                    count += 1
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except OSError:
                        pass
        return count

    def stats(self) -> dict[str, int]:
        """Get cache statistics."""
        total_entries = 0
        total_bytes = 0
        for root, _dirs, files in os.walk(self.cache_dir):
            for f in files:
                if f.endswith(".json"):
                    total_entries += 1
                    try:
                        total_bytes += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
        return {"total_entries": total_entries, "total_bytes": total_bytes}
