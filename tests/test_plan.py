"""Tests for audit planner."""
import argparse

import pytest

from cb.commands.plan import (
    _build_plan, _has_ipc, _has_objc, _has_parsers, _build_pipeline_command,
)


def _make_args(**kwargs):
    defaults = {
        "binary": "/usr/bin/file",
        "from_triage": None,
        "deep": False,
        "quick": False,
        "crash_dir": None,
        "no_cache": True,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_triage(**kwargs):
    base = {
        "file_info": {"format": "macho"},
        "protections": {},
        "imports_summary": {
            "total_imports": 10,
            "categories": {},
        },
    }
    base.update(kwargs)
    return base


class TestDetection:
    def test_has_ipc_from_categories(self):
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"ipc": ["mach_msg"]}
        assert _has_ipc(triage) is True

    def test_has_ipc_from_xpc_category(self):
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"xpc": ["xpc_connection_create"]}
        assert _has_ipc(triage) is True

    def test_no_ipc(self):
        triage = _make_triage()
        assert _has_ipc(triage) is False

    def test_has_objc(self):
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"objc": ["objc_msgSend"]}
        assert _has_objc(triage) is True

    def test_no_objc(self):
        triage = _make_triage()
        assert _has_objc(triage) is False

    def test_has_parsers(self):
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"image": ["CGImageCreate"]}
        assert _has_parsers(triage) is True

    def test_no_parsers(self):
        triage = _make_triage()
        assert _has_parsers(triage) is False


class TestBuildPlan:
    def test_always_includes_core_3(self):
        args = _make_args()
        triage = _make_triage()
        steps = _build_plan(args.binary, triage, args)
        commands = [s["command"] for s in steps]
        assert any("triage" in c for c in commands)
        assert any("attack" in c for c in commands)
        assert any("vuln" in c for c in commands)

    def test_ipc_triggers_ipc_step(self):
        args = _make_args()
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"ipc": ["mach_msg"]}
        steps = _build_plan(args.binary, triage, args)
        commands = [s["command"] for s in steps]
        assert any("cb ipc" in c for c in commands)
        assert any("cb sandbox" in c for c in commands)

    def test_objc_triggers_objc_step(self):
        args = _make_args()
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"objc": ["objc_msgSend"]}
        steps = _build_plan(args.binary, triage, args)
        commands = [s["command"] for s in steps]
        assert any("cb objc" in c for c in commands)

    def test_quick_reduces_steps(self):
        args = _make_args(quick=True)
        triage = _make_triage()
        triage["imports_summary"]["categories"] = {"ipc": ["mach_msg"],
                                                    "objc": ["objc_msgSend"]}
        all_steps = _build_plan(args.binary, triage, args)
        quick_steps = [s for s in all_steps if s["priority"] == 1]
        assert len(quick_steps) < len(all_steps)

    def test_from_triage_skips_triage_step(self):
        args = _make_args(from_triage="/tmp/triage.json")
        triage = _make_triage()
        steps = _build_plan(args.binary, triage, args)
        commands = [s["command"] for s in steps]
        assert not any("cb triage" in c for c in commands)

    def test_pipeline_command_parseable(self):
        args = _make_args()
        triage = _make_triage()
        steps = _build_plan(args.binary, triage, args)
        pipeline = _build_pipeline_command(steps)
        assert isinstance(pipeline, str)
        assert "&&" in pipeline or len(steps) == 1

    def test_time_estimate_positive(self):
        args = _make_args()
        triage = _make_triage()
        steps = _build_plan(args.binary, triage, args)
        total_time = sum(s.get("estimated_seconds", 0) for s in steps)
        assert total_time > 0

    def test_always_ends_with_report(self):
        args = _make_args()
        triage = _make_triage()
        steps = _build_plan(args.binary, triage, args)
        assert "cb report" in steps[-1]["command"]

    def test_step_dependencies_valid(self):
        args = _make_args()
        triage = _make_triage()
        steps = _build_plan(args.binary, triage, args)
        for step in steps:
            assert isinstance(step["depends_on"], list)
            assert isinstance(step["priority"], int)
            assert step["priority"] >= 1
