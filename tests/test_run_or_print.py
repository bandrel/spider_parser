from types import SimpleNamespace

import pytest

import spider_parser
from spider_parser import run_or_print


def test_dry_run_prints_and_does_not_execute(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(spider_parser.subprocess, "run",
                        lambda *a, **kw: called.append((a, kw)) or SimpleNamespace(returncode=0))
    run_or_print("echo hi", do_exec=False)
    out = capsys.readouterr().out
    assert out == "echo hi\n"
    assert called == []


def test_exec_prints_then_runs_with_shell_true(monkeypatch, capsys):
    called = []
    def fake_run(cmd, **kwargs):
        called.append((cmd, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(spider_parser.subprocess, "run", fake_run)
    run_or_print("echo hi", do_exec=True)
    out = capsys.readouterr().out
    assert out == "echo hi\n"
    assert len(called) == 1
    cmd, kwargs = called[0]
    assert cmd == "echo hi"
    assert kwargs.get("shell") is True


def test_exec_exits_with_non_zero_returncode(monkeypatch, capsys):
    monkeypatch.setattr(spider_parser.subprocess, "run",
                        lambda *a, **kw: SimpleNamespace(returncode=2))
    with pytest.raises(SystemExit) as exc:
        run_or_print("false", do_exec=True)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "ERROR: command failed (exit 2): false" in err
