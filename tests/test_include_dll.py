import json
import sys

from spider_parser import main


def _make_input_file(tmp_path, hostname, shares):
    d = tmp_path / "input"
    d.mkdir()
    (d / f"{hostname}.json").write_text(json.dumps(shares))
    return d


def _run_main(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", argv)
    main()
    return capsys.readouterr()


def test_dll_files_excluded_by_default(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "host", {"C$": ["app.dll", "notes.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", ".",
    ])
    assert "host,C$,app.dll" not in out.out
    assert "host,C$,notes.txt" in out.out


def test_dll_files_included_with_flag(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "host", {"C$": ["app.dll", "notes.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--include-dll", ".",
    ])
    assert "host,C$,app.dll" in out.out
    assert "host,C$,notes.txt" in out.out


def test_dll_exclusion_is_case_insensitive(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "host", {"C$": ["APP.DLL"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", ".",
    ])
    assert "APP.DLL" not in out.out


def test_dll_exclusion_uses_basename_of_backslash_path(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "host", {"C$": [r"Windows\System32\app.dll"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", ".",
    ])
    assert "app.dll" not in out.out


def test_preset_keyword_matches_basename_only_not_directory(tmp_path, monkeypatch, capsys):
    """A 'private' directory in the path must not match when the file itself doesn't."""
    d = _make_input_file(tmp_path, "host", {
        "C$": [r"Private\readme.txt", r"keys\id_rsa"],
    })
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "-P", "keys",
    ])
    assert "readme.txt" not in out.out   # only the directory was "private"
    assert "id_rsa" in out.out           # basename actually matches
