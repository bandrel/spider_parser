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


def test_exec_mount_runs_mkdir_then_mount_per_share(tmp_path, monkeypatch):
    d = _make_input(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(spider_parser.subprocess, "run", fake_run)

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-m", "--exec", "-u", "alice", "-p", "hunter2", "password",
    ])
    main()
    # Two calls per share: mkdir, then mount.
    assert len(calls) == 2
    assert calls[0].startswith("mkdir -p ")
    assert calls[1].startswith("mount -t cifs ")


def test_exec_mount_failing_mkdir_aborts_before_mount(tmp_path, monkeypatch):
    d = _make_input(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        # mkdir fails; mount should never run.
        return SimpleNamespace(returncode=1 if cmd.startswith("mkdir") else 0)
    monkeypatch.setattr(spider_parser.subprocess, "run", fake_run)

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-m", "--exec", "-u", "alice", "-p", "hunter2", "password",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert len(calls) == 1
    assert calls[0].startswith("mkdir -p ")


def test_exec_mount_then_acl_fail_fast_aborts_acl_block(tmp_path, monkeypatch):
    d = _make_input(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        # mount fails; acl block should never run.
        return SimpleNamespace(returncode=1 if cmd.startswith("mount") else 0)
    monkeypatch.setattr(spider_parser.subprocess, "run", fake_run)

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-m", "-a", "--exec",
        "-u", "alice", "-p", "hunter2", "password",
    ])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    # mkdir + mount ran; smbcacls did not.
    assert [c.split()[0] for c in calls] == ["mkdir", "mount"]


def test_dry_run_mount_runs_zero_subprocesses(tmp_path, monkeypatch, capsys):
    d = _make_input(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    calls = []
    monkeypatch.setattr(spider_parser.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or SimpleNamespace(returncode=0))

    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/",
        "-m", "--dry-run", "-u", "alice", "-p", "hunter2", "password",
    ])
    main()
    out = capsys.readouterr().out
    assert "mkdir -p " in out
    assert "mount -t cifs " in out
    assert calls == []
