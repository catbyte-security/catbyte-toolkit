"""Tests for session management command."""
import argparse
import json
import os
import shutil
import tempfile

import pytest

from cb.commands.session import (
    PHASES,
    _current_phase,
    _load_session,
    _save_session,
    _session_path,
    _sessions_dir,
    _run_create,
    _run_status,
    _run_save,
    _run_load,
    _run_list,
    _run_next,
)


@pytest.fixture
def tmp_sessions(tmp_path, monkeypatch):
    """Redirect sessions dir to a temp directory."""
    session_dir = str(tmp_path / "sessions")
    monkeypatch.setattr("cb.commands.session._sessions_dir", lambda: session_dir)
    monkeypatch.setattr("cb.commands.session._session_path",
                        lambda name: os.path.join(session_dir, name))
    monkeypatch.setattr("cb.commands.session._session_json_path",
                        lambda name: os.path.join(session_dir, name, "session.json"))
    return session_dir


def _make_args(**kwargs):
    defaults = {
        "format": "json",
        "max_results": 50,
        "quiet": True,
        "output": None,
        "no_cache": True,
        "budget": None,
        "verbose": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestCreateSession:
    def test_create_session_creates_dir_and_json(self, tmp_sessions, capsys):
        args = _make_args(name="test-audit", target="/usr/bin/file")
        _run_create(args)

        session_dir = os.path.join(tmp_sessions, "test-audit")
        assert os.path.isdir(session_dir)
        assert os.path.exists(os.path.join(session_dir, "session.json"))

        with open(os.path.join(session_dir, "session.json")) as f:
            session = json.load(f)
        assert session["name"] == "test-audit"
        assert session["target"] == "/usr/bin/file"
        assert session["current_phase"] == "recon"
        assert session["phases"]["recon"]["status"] == "in_progress"
        for phase in PHASES[1:]:
            assert session["phases"][phase]["status"] == "pending"

    def test_create_session_outputs_json(self, tmp_sessions, capsys):
        args = _make_args(name="test-audit", target="/usr/bin/file")
        _run_create(args)

        output = json.loads(capsys.readouterr().out)
        assert output["session"] == "test-audit"
        assert output["target"] == "/usr/bin/file"
        assert output["current_phase"] == "recon"

    def test_create_duplicate_session_errors(self, tmp_sessions, capsys):
        args = _make_args(name="dup-test", target="/usr/bin/file")
        _run_create(args)
        capsys.readouterr()

        _run_create(args)
        output = json.loads(capsys.readouterr().out)
        assert "error" in output


class TestStatusSession:
    def test_status_nonexistent_session_returns_error(self, tmp_sessions, capsys):
        args = _make_args(name="nonexistent")
        _run_status(args)

        output = json.loads(capsys.readouterr().out)
        assert "error" in output

    def test_status_shows_current_phase(self, tmp_sessions, capsys):
        create_args = _make_args(name="status-test", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        status_args = _make_args(name="status-test")
        _run_status(status_args)

        output = json.loads(capsys.readouterr().out)
        assert output["current_phase"] == "recon"
        assert output["session"] == "status-test"

    def test_status_no_name_uses_most_recent(self, tmp_sessions, capsys):
        args1 = _make_args(name="old-session", target="/bin/ls")
        _run_create(args1)
        capsys.readouterr()

        args2 = _make_args(name="new-session", target="/bin/cat")
        _run_create(args2)
        capsys.readouterr()

        # Ensure new-session has a later updated_at timestamp
        session_file = os.path.join(tmp_sessions, "new-session", "session.json")
        with open(session_file) as f:
            s = json.load(f)
        s["updated_at"] = "2099-01-01T00:00:00Z"
        with open(session_file, "w") as f:
            json.dump(s, f)

        status_args = _make_args(name=None)
        _run_status(status_args)
        output = json.loads(capsys.readouterr().out)
        assert output["session"] == "new-session"

    def test_status_no_sessions_returns_error(self, tmp_sessions, capsys):
        args = _make_args(name=None)
        _run_status(args)

        output = json.loads(capsys.readouterr().out)
        assert "error" in output


class TestSaveLoadRoundtrip:
    def test_save_and_load_preserves_data(self, tmp_sessions, capsys):
        # Create session
        create_args = _make_args(name="roundtrip", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        # Save recon data to file
        test_data = {"findings": [{"vuln": "buffer_overflow", "severity": "high"}]}
        data_file = os.path.join(tmp_sessions, "recon_data.json")
        with open(data_file, "w") as f:
            json.dump(test_data, f)

        save_args = _make_args(phase="recon", data=data_file, session="roundtrip")
        _run_save(save_args)
        capsys.readouterr()

        # Load recon data
        load_args = _make_args(phase="recon", session="roundtrip")
        _run_load(load_args)
        output = json.loads(capsys.readouterr().out)

        # Verify roundtrip
        assert output["findings"] == test_data["findings"]

    def test_save_updates_phase_status(self, tmp_sessions, capsys):
        create_args = _make_args(name="save-test", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        save_args = _make_args(phase="recon", data=None, session="save-test")
        _run_save(save_args)
        capsys.readouterr()

        # Check session was updated
        session_file = os.path.join(tmp_sessions, "save-test", "session.json")
        with open(session_file) as f:
            session = json.load(f)
        assert session["phases"]["recon"]["status"] == "completed"
        assert session["phases"]["static"]["status"] == "in_progress"

    def test_load_nonexistent_phase_returns_error(self, tmp_sessions, capsys):
        create_args = _make_args(name="load-err", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        load_args = _make_args(phase="static", session="load-err")
        _run_load(load_args)
        output = json.loads(capsys.readouterr().out)
        assert "error" in output


class TestPhaseOrdering:
    def test_cannot_skip_phases(self, tmp_sessions, capsys):
        create_args = _make_args(name="skip-test", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        # Try to save "static" without completing "recon"
        save_args = _make_args(phase="static", data=None, session="skip-test")
        _run_save(save_args)
        output = json.loads(capsys.readouterr().out)
        assert "error" in output
        assert "recon" in output["error"]

    def test_cannot_skip_to_verified(self, tmp_sessions, capsys):
        create_args = _make_args(name="skip-v", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        save_args = _make_args(phase="verified", data=None, session="skip-v")
        _run_save(save_args)
        output = json.loads(capsys.readouterr().out)
        assert "error" in output

    def test_sequential_phases_work(self, tmp_sessions, capsys):
        create_args = _make_args(name="seq-test", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        for phase in PHASES:
            save_args = _make_args(phase=phase, data=None, session="seq-test")
            _run_save(save_args)
            capsys.readouterr()

        # All phases should be completed
        session_file = os.path.join(tmp_sessions, "seq-test", "session.json")
        with open(session_file) as f:
            session = json.load(f)
        for phase in PHASES:
            assert session["phases"][phase]["status"] == "completed"


class TestListSessions:
    def test_list_returns_all_sessions(self, tmp_sessions, capsys):
        for name in ["alpha", "beta", "gamma"]:
            args = _make_args(name=name, target=f"/bin/{name}")
            _run_create(args)
            capsys.readouterr()

        list_args = _make_args()
        _run_list(list_args)
        output = json.loads(capsys.readouterr().out)

        assert output["total"] == 3
        names = {s["name"] for s in output["sessions"]}
        assert names == {"alpha", "beta", "gamma"}

    def test_list_empty_returns_empty(self, tmp_sessions, capsys):
        list_args = _make_args()
        _run_list(list_args)
        output = json.loads(capsys.readouterr().out)
        assert output["sessions"] == []


class TestNextPhase:
    def test_next_recommends_recon_initially(self, tmp_sessions, capsys):
        create_args = _make_args(name="next-test", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        next_args = _make_args(session="next-test")
        _run_next(next_args)
        output = json.loads(capsys.readouterr().out)

        assert output["next_phase"] == "recon"
        assert "commands" in output

    def test_next_advances_after_save(self, tmp_sessions, capsys):
        create_args = _make_args(name="next-adv", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        save_args = _make_args(phase="recon", data=None, session="next-adv")
        _run_save(save_args)
        capsys.readouterr()

        next_args = _make_args(session="next-adv")
        _run_next(next_args)
        output = json.loads(capsys.readouterr().out)
        assert output["next_phase"] == "static"

    def test_next_all_completed(self, tmp_sessions, capsys):
        create_args = _make_args(name="done-test", target="/usr/bin/file")
        _run_create(create_args)
        capsys.readouterr()

        for phase in PHASES:
            save_args = _make_args(phase=phase, data=None, session="done-test")
            _run_save(save_args)
            capsys.readouterr()

        next_args = _make_args(session="done-test")
        _run_next(next_args)
        output = json.loads(capsys.readouterr().out)
        assert output["completed"] is True


class TestCurrentPhase:
    def test_current_phase_initial(self):
        session = {
            "phases": {phase: {"status": "pending"} for phase in PHASES}
        }
        assert _current_phase(session) == "recon"

    def test_current_phase_after_recon(self):
        session = {
            "phases": {phase: {"status": "pending"} for phase in PHASES}
        }
        session["phases"]["recon"]["status"] = "completed"
        assert _current_phase(session) == "static"

    def test_current_phase_all_done(self):
        session = {
            "phases": {phase: {"status": "completed"} for phase in PHASES}
        }
        assert _current_phase(session) == "report"
