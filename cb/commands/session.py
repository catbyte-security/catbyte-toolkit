"""cb session - Audit session management with state handoff between phases."""
import argparse
import json
import os
import sys
import time

from cb.output import add_output_args, make_formatter, load_piped_input


PHASES = ["recon", "static", "verified", "exploit", "report"]

PHASE_COMMANDS = {
    "recon": "cb triage {target} --full && cb attack {target}",
    "static": "cb vuln {target} && cb grep {target}",
    "verified": "cb verify {target} <findings_file>",
    "exploit": "cb gadget {target} && cb heap {target}",
    "report": "cb report {target}",
}


def _sessions_dir():
    from cb.config import load_config
    cfg = load_config()
    return cfg.get("session_dir", os.path.expanduser("~/.cb/sessions"))


def _session_path(name):
    return os.path.join(_sessions_dir(), name)


def _session_json_path(name):
    return os.path.join(_session_path(name), "session.json")


def _load_session(name):
    path = _session_json_path(name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _save_session(name, data):
    path = _session_json_path(name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _most_recent_session():
    base = _sessions_dir()
    if not os.path.isdir(base):
        return None
    sessions = []
    for entry in os.listdir(base):
        sp = os.path.join(base, entry, "session.json")
        if os.path.exists(sp):
            with open(sp) as f:
                s = json.load(f)
            sessions.append(s)
    if not sessions:
        return None
    return max(sessions, key=lambda s: s.get("updated_at", s.get("created_at", "")))


def _current_phase(session):
    for phase in PHASES:
        status = session["phases"][phase]["status"]
        if status != "completed":
            return phase
    return PHASES[-1]


def _findings_count(session):
    count = 0
    for phase in PHASES:
        phase_file = os.path.join(_session_path(session["name"]), f"{phase}.json")
        if os.path.exists(phase_file):
            try:
                with open(phase_file) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list):
                            count += len(v)
                elif isinstance(data, list):
                    count += len(data)
            except (json.JSONDecodeError, OSError):
                pass
    return count


def register(subparsers):
    p = subparsers.add_parser("session", help="Manage audit sessions with state handoff")
    sp = p.add_subparsers(dest="session_command", help="Session subcommands")

    # create
    c = sp.add_parser("create", help="Create a new audit session")
    c.add_argument("name", help="Session name")
    c.add_argument("--target", required=True, help="Target binary or URL")
    add_output_args(c)
    c.set_defaults(func=_run_create)

    # status
    s = sp.add_parser("status", help="Show session status")
    s.add_argument("name", nargs="?", default=None, help="Session name (default: most recent)")
    add_output_args(s)
    s.set_defaults(func=_run_status)

    # save
    sv = sp.add_parser("save", help="Save phase output to session")
    sv.add_argument("phase", choices=PHASES, help="Phase to save")
    sv.add_argument("--data", default=None, help="File path or '-' for stdin")
    sv.add_argument("--session", default=None, help="Session name (default: most recent)")
    add_output_args(sv)
    sv.set_defaults(func=_run_save)

    # load
    ld = sp.add_parser("load", help="Load saved phase data")
    ld.add_argument("phase", choices=PHASES, help="Phase to load")
    ld.add_argument("--session", default=None, help="Session name (default: most recent)")
    add_output_args(ld)
    ld.set_defaults(func=_run_load)

    # list
    ls = sp.add_parser("list", help="List all sessions")
    add_output_args(ls)
    ls.set_defaults(func=_run_list)

    # next
    nx = sp.add_parser("next", help="Show next recommended phase")
    nx.add_argument("--session", default=None, help="Session name (default: most recent)")
    add_output_args(nx)
    nx.set_defaults(func=_run_next)

    p.set_defaults(func=lambda args: p.print_help())


def run(args):
    args.func(args)


def _run_create(args):
    fmt = make_formatter(args)
    name = args.name
    target = args.target

    session_dir = _session_path(name)
    if os.path.exists(session_dir):
        fmt.status(f"Session '{name}' already exists")
        fmt.emit({"error": f"Session '{name}' already exists"}, "session")
        return

    os.makedirs(session_dir, exist_ok=True)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    session = {
        "name": name,
        "target": target,
        "created_at": now,
        "updated_at": now,
        "current_phase": "recon",
        "phases": {
            phase: {"status": "pending"} for phase in PHASES
        },
    }
    session["phases"]["recon"]["status"] = "in_progress"

    _save_session(name, session)
    fmt.status(f"Created session '{name}' targeting '{target}'")
    fmt.emit({
        "session": name,
        "target": target,
        "created_at": now,
        "current_phase": "recon",
        "session_dir": session_dir,
    }, "session")


def _run_status(args):
    fmt = make_formatter(args)
    name = args.name

    if name:
        session = _load_session(name)
    else:
        session = _most_recent_session()

    if not session:
        msg = f"Session '{name}' not found" if name else "No sessions found"
        fmt.status(msg)
        fmt.emit({"error": msg}, "session")
        return

    phase = _current_phase(session)
    findings = _findings_count(session)

    fmt.emit({
        "session": session["name"],
        "target": session["target"],
        "current_phase": phase,
        "findings_count": findings,
        "created_at": session["created_at"],
        "updated_at": session["updated_at"],
        "phases": session["phases"],
    }, "session")


def _run_save(args):
    fmt = make_formatter(args)
    phase = args.phase
    session_name = args.session

    if session_name:
        session = _load_session(session_name)
    else:
        session = _most_recent_session()

    if not session:
        msg = f"Session '{session_name}' not found" if session_name else "No sessions found"
        fmt.status(msg)
        fmt.emit({"error": msg}, "session")
        return

    name = session["name"]

    # Validate phase ordering
    phase_idx = PHASES.index(phase)
    for i in range(phase_idx):
        prev_phase = PHASES[i]
        if session["phases"][prev_phase]["status"] != "completed":
            fmt.status(f"Cannot save '{phase}': phase '{prev_phase}' not completed yet")
            fmt.emit({
                "error": f"Phase '{prev_phase}' must be completed before '{phase}'",
                "blocking_phase": prev_phase,
                "requested_phase": phase,
            }, "session")
            return

    # Load data from file or stdin
    data = None
    if args.data:
        if args.data == "-":
            data = load_piped_input()
            if data is None:
                # Try reading stdin directly
                try:
                    raw = sys.stdin.read()
                    if raw.strip():
                        data = json.loads(raw)
                except (json.JSONDecodeError, Exception):
                    pass
        else:
            try:
                with open(args.data) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                fmt.status(f"Failed to load data: {e}")
                fmt.emit({"error": f"Failed to load data: {e}"}, "session")
                return

    if data is None:
        data = {"phase": phase, "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # Save phase data
    phase_file = os.path.join(_session_path(name), f"{phase}.json")
    with open(phase_file, "w") as f:
        json.dump(data, f, indent=2)

    # Update session
    session["phases"][phase]["status"] = "completed"
    session["phases"][phase]["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # Mark next phase as in_progress
    phase_idx = PHASES.index(phase)
    if phase_idx + 1 < len(PHASES):
        next_phase = PHASES[phase_idx + 1]
        if session["phases"][next_phase]["status"] == "pending":
            session["phases"][next_phase]["status"] = "in_progress"
    session["current_phase"] = _current_phase(session)
    session["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save_session(name, session)

    fmt.status(f"Saved '{phase}' data for session '{name}'")
    fmt.emit({
        "session": name,
        "phase": phase,
        "status": "completed",
        "data_file": phase_file,
    }, "session")


def _run_load(args):
    fmt = make_formatter(args)
    phase = args.phase
    session_name = args.session

    if session_name:
        session = _load_session(session_name)
    else:
        session = _most_recent_session()

    if not session:
        msg = f"Session '{session_name}' not found" if session_name else "No sessions found"
        fmt.status(msg)
        fmt.emit({"error": msg}, "session")
        return

    name = session["name"]
    phase_file = os.path.join(_session_path(name), f"{phase}.json")

    if not os.path.exists(phase_file):
        fmt.status(f"No data for phase '{phase}' in session '{name}'")
        fmt.emit({"error": f"No data for phase '{phase}'"}, "session")
        return

    with open(phase_file) as f:
        data = json.load(f)

    fmt.emit(data, "session")


def _run_list(args):
    fmt = make_formatter(args)
    base = _sessions_dir()

    if not os.path.isdir(base):
        fmt.emit({"sessions": []}, "session")
        return

    sessions = []
    for entry in sorted(os.listdir(base)):
        sp = os.path.join(base, entry, "session.json")
        if os.path.exists(sp):
            try:
                with open(sp) as f:
                    s = json.load(f)
                sessions.append({
                    "name": s["name"],
                    "target": s["target"],
                    "current_phase": _current_phase(s),
                    "created_at": s["created_at"],
                })
            except (json.JSONDecodeError, OSError, KeyError):
                pass

    fmt.emit({"sessions": sessions, "total": len(sessions)}, "session")


def _run_next(args):
    fmt = make_formatter(args)
    session_name = args.session

    if session_name:
        session = _load_session(session_name)
    else:
        session = _most_recent_session()

    if not session:
        msg = f"Session '{session_name}' not found" if session_name else "No sessions found"
        fmt.status(msg)
        fmt.emit({"error": msg}, "session")
        return

    name = session["name"]
    target = session["target"]

    # Find next incomplete phase
    next_phase = None
    for phase in PHASES:
        if session["phases"][phase]["status"] != "completed":
            next_phase = phase
            break

    if next_phase is None:
        fmt.emit({
            "session": name,
            "message": "All phases completed",
            "completed": True,
        }, "session")
        return

    commands = PHASE_COMMANDS.get(next_phase, "").format(target=target)

    fmt.emit({
        "session": name,
        "next_phase": next_phase,
        "commands": commands,
        "save_command": f"cb session save {next_phase} --session {name} --data -",
    }, "session")


def main():
    parser = argparse.ArgumentParser(prog="cbsession",
                                     description="Audit session management")
    sp = parser.add_subparsers(dest="session_command", help="Session subcommands")

    c = sp.add_parser("create", help="Create a new audit session")
    c.add_argument("name", help="Session name")
    c.add_argument("--target", required=True, help="Target binary or URL")
    add_output_args(c)
    c.set_defaults(func=_run_create)

    s = sp.add_parser("status", help="Show session status")
    s.add_argument("name", nargs="?", default=None)
    add_output_args(s)
    s.set_defaults(func=_run_status)

    sv = sp.add_parser("save", help="Save phase output to session")
    sv.add_argument("phase", choices=PHASES)
    sv.add_argument("--data", default=None)
    sv.add_argument("--session", default=None)
    add_output_args(sv)
    sv.set_defaults(func=_run_save)

    ld = sp.add_parser("load", help="Load saved phase data")
    ld.add_argument("phase", choices=PHASES)
    ld.add_argument("--session", default=None)
    add_output_args(ld)
    ld.set_defaults(func=_run_load)

    ls = sp.add_parser("list", help="List all sessions")
    add_output_args(ls)
    ls.set_defaults(func=_run_list)

    nx = sp.add_parser("next", help="Show next recommended phase")
    nx.add_argument("--session", default=None)
    add_output_args(nx)
    nx.set_defaults(func=_run_next)

    args = parser.parse_args()
    if not args.session_command:
        parser.print_help()
        sys.exit(1)
    args.func(args)
