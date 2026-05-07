import json
import sys
from types import SimpleNamespace

import pytest

import spider_parser
from spider_parser import main


def _make_input(tmp_path, hostname, shares):
    d = tmp_path / "input"
    d.mkdir()
    (d / f"{hostname}.json").write_text(json.dumps(shares))
    return d


def test_exec_acl_runs_subprocess_per_smbcacls_line(tmp_path, monkeypatch, capsys):
    d = _make_input(tmp_path, "127.0.0.1", {
        "C$": ["password.txt"],
        "ADMIN$": ["password.txt"],
    })
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(spider_parser.subprocess, "run", fake_run)

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-a", "--exec", "-u", "alice", "-p", "hunter2", "password",
    ])
    main()
    # Two shares → two smbcacls executions, in sorted order.
    assert calls == [
        "smbcacls '//127.0.0.1/ADMIN$' '/' -U 'alice%hunter2'",
        "smbcacls '//127.0.0.1/C$' '/' -U 'alice%hunter2'",
    ]


def test_dry_run_acl_runs_zero_subprocesses(tmp_path, monkeypatch, capsys):
    d = _make_input(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    calls = []
    monkeypatch.setattr(spider_parser.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or SimpleNamespace(returncode=0))

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-a", "--dry-run", "-u", "alice", "-p", "hunter2", "password",
    ])
    main()
    out = capsys.readouterr().out
    assert "smbcacls '//127.0.0.1/C$' '/' -U 'alice%hunter2'" in out
    assert calls == []


def test_exec_acl_fail_fast_aborts_remaining_shares(tmp_path, monkeypatch, capsys):
    d = _make_input(tmp_path, "127.0.0.1", {
        "ADMIN$": ["password.txt"],
        "C$": ["password.txt"],
        "D$": ["password.txt"],
    })
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        # Fail on second share (C$, since order is sorted).
        return SimpleNamespace(returncode=1 if "C$" in cmd else 0)
    monkeypatch.setattr(spider_parser.subprocess, "run", fake_run)

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-a", "--exec", "-u", "alice", "-p", "hunter2", "password",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    # ADMIN$ ran (returned 0), C$ ran (returned 1, triggered exit), D$ never ran.
    assert len(calls) == 2
    assert "ADMIN$" in calls[0]
    assert "C$" in calls[1]
