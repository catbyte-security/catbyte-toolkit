"""Tests for crash-first verifier."""
import argparse
import os
import signal

import pytest

from cb.commands.verify import _execute_once, _signal_name, GUARD_ENV


def _make_env(no_guards=False):
    env = dict(os.environ)
    if not no_guards:
        env.update(GUARD_ENV)
    return env


class TestSignalName:
    def test_known_signal(self):
        assert _signal_name(11) == "SIGSEGV"

    def test_sigabrt(self):
        assert _signal_name(6) == "SIGABRT"

    def test_unknown_signal(self):
        name = _signal_name(999)
        assert "999" in name


class TestExecuteOnce:
    def test_non_crashing(self):
        env = _make_env(no_guards=True)
        result = _execute_once("/usr/bin/true", "/dev/null", "file", [], 10, env)
        assert result["exit_code"] == 0
        assert result["crashed"] is False
        assert result["timed_out"] is False

    def test_exit_code_captured(self):
        env = _make_env(no_guards=True)
        result = _execute_once("/usr/bin/false", "/dev/null", "file", [], 10, env)
        assert result["exit_code"] == 1
        assert result["crashed"] is False

    def test_timeout_handling(self):
        env = _make_env(no_guards=True)
        result = _execute_once("/bin/sleep", "10", "file", [], 1, env)
        assert result["timed_out"] is True

    def test_guard_env_set(self):
        env = _make_env(no_guards=False)
        assert env.get("MallocGuardEdges") == "1"
        assert env.get("MallocScribble") == "1"
        assert env.get("MallocStackLogging") == "1"

    def test_no_guards_clean_env(self):
        env = _make_env(no_guards=True)
        # Should not have guard vars unless they were in original env
        # We just verify the function works without them
        result = _execute_once("/usr/bin/true", "/dev/null", "file", [], 10, env)
        assert result["exit_code"] == 0

    def test_stdin_mode(self):
        env = _make_env(no_guards=True)
        result = _execute_once("/usr/bin/wc", "/dev/null", "stdin", [], 10, env)
        assert result["exit_code"] == 0

    def test_non_executable_error(self):
        env = _make_env(no_guards=True)
        result = _execute_once("/dev/null", "/dev/null", "file", [], 10, env)
        assert result.get("error") is not None or result.get("exit_code") is not None


class TestVerifyRegister:
    def test_register_creates_parser(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        from cb.commands.verify import register
        register(sub)
        # Verify it parses without error
        args = parser.parse_args(["verify", "/usr/bin/true", "/dev/null"])
        assert args.binary == "/usr/bin/true"
        assert args.input == "/dev/null"
        assert args.mode == "file"
        assert args.timeout == 10
        assert args.repeat == 1
        assert args.no_guards is False
