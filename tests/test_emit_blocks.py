import json
import socket
import sys

import pytest

from spider_parser import main


def _make_input_file(tmp_path, hostname, shares):
    """Create a spider_plus-style JSON file. Returns the input dir."""
    d = tmp_path / "input"
    d.mkdir()
    (d / f"{hostname}.json").write_text(json.dumps(shares))
    return d


def _run_main(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", argv)
    main()
    return capsys.readouterr()


def test_acl_ntlm_emits_expected_lines(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "127.0.0.1", {"C$": ["secret_password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-a", "-u", "alice", "-p", "hunter2", "password",
    ])
    assert "# 127.0.0.1 / C$ \u2014 DACL audit" in out.out
    assert "smbcacls '//127.0.0.1/C$' '/' -U 'alice%hunter2'" in out.out
    assert "rpcclient" not in out.out


def test_acl_ntlm_with_domain_emits_user_at_domain_format(tmp_path, monkeypatch, capsys):
    """When -D/--domain is set, NTLM auth becomes -U 'user@domain%password'."""
    d = _make_input_file(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-a", "-u", "alice", "-p", "hunter2", "-D", "CORP", "password",
    ])
    assert "smbcacls '//127.0.0.1/C$' '/' -U 'alice@CORP%hunter2'" in out.out


def test_acl_kerberos_emits_expected_lines(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "127.0.0.1", {"SYSVOL": ["password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-a", "-k", "--ccache", "/tmp/USER.ccache",
        "-u", "DOMAIN.COM/USER",
        "--include-sysvol", "password",
    ])
    assert "# 127.0.0.1 / SYSVOL \u2014 DACL audit" in out.out
    # shlex.quote leaves safe UNCs unquoted; the auth fragment is quoted by build_smb_auth.
    assert "smbcacls //127.0.0.1/SYSVOL '/' --use-krb5-ccache=/tmp/USER.ccache -U 'DOMAIN.COM/USER'" in out.out
    assert "rpcclient" not in out.out


def test_acl_share_with_space_is_shell_quoted(tmp_path, monkeypatch, capsys):
    """Regression: share names with spaces must not split the smbcacls UNC arg."""
    d = _make_input_file(tmp_path, "127.0.0.1", {"My Share": ["password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-a", "-u", "alice", "-p", "hunter2", "password",
    ])
    # The UNC must be wrapped in single quotes so the space stays inside one argument.
    assert "smbcacls '//127.0.0.1/My Share' '/' -U 'alice%hunter2'" in out.out


def test_combined_mount_acl_separates_blocks_with_blank_line(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-m", "-a", "-u", "alice", "-p", "hunter2", "password",
    ])
    # Mount line, blank line, then DACL audit header — verify ordering.
    lines = out.out.splitlines()
    mount_idx = next(i for i, l in enumerate(lines) if l.startswith("mount -t cifs"))
    acl_idx = next(i for i, l in enumerate(lines) if l.startswith("# 127.0.0.1 / C$"))
    assert mount_idx < acl_idx
    assert lines[mount_idx + 1] == ""  # blank line separator


def test_mount_only_no_blank_line_without_acl(tmp_path, monkeypatch, capsys):
    d = _make_input_file(tmp_path, "127.0.0.1", {"C$": ["password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-m", "-u", "alice", "-p", "hunter2", "password",
    ])
    # No DACL audit comments appear, no trailing blank line from acl branch.
    assert "DACL audit" not in out.out


def test_mount_acl_no_spurious_blank_when_dns_fails(tmp_path, monkeypatch, capsys):
    """Regression: when all DNS lookups fail, --mount --acl must emit no stdout
    and in particular no spurious blank-only line between the two blocks."""
    def _fail(hostname):
        raise socket.gaierror(f"no such host: {hostname}")
    monkeypatch.setattr(socket, "gethostbyname", _fail)
    d = _make_input_file(tmp_path, "host.example.invalid", {"C$": ["password.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/",
        "-m", "-a", "-u", "alice", "-p", "hunter2", "password",
    ])
    assert "# " not in out.out
    assert "smbcacls" not in out.out
    assert "rpcclient" not in out.out
    # No blank-only line: every emitted line should be non-empty (no spurious
    # separator from the --acl branch when --mount produced zero lines).
    assert all(line != "" for line in out.out.splitlines())
