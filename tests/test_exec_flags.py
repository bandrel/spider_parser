import sys

import pytest

from spider_parser import main


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", argv)
    main()


def test_exec_and_dry_run_are_mutually_exclusive(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, [
            "spider-parser", "-a", "--exec", "--dry-run",
            "-u", "alice", "-p", "hunter2", "password",
        ])
    err = capsys.readouterr().err
    assert "not allowed with" in err or "mutually exclusive" in err


def test_exec_requires_mount_or_acl(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, [
            "spider-parser", "--exec",
            "-u", "alice", "-p", "hunter2", "password",
        ])
    err = capsys.readouterr().err
    assert "--exec requires --mount or --acl" in err


def test_dry_run_without_mount_or_acl_is_allowed(monkeypatch, tmp_path, capsys):
    """--dry-run without -m/-a is a no-op, not an error."""
    d = tmp_path / "input"
    d.mkdir()
    (d / "host.json").write_text('{"C$": ["password.txt"]}')
    monkeypatch.setattr(sys, "argv", [
        "spider-parser", "-d", f"{d}/", "--dry-run", "password",
    ])
    main()
    out = capsys.readouterr().out
    assert "host,C$,password.txt" in out
