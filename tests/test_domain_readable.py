import json
import sys

from spider_parser import _trustee_is_domain, is_domain_readable, main


def test_trustee_is_domain_matches_domain_users_with_prefix():
    assert _trustee_is_domain("DOMAIN\\Domain Users") is True


def test_trustee_is_domain_matches_builtin_users():
    assert _trustee_is_domain("BUILTIN\\Users") is True


def test_trustee_is_domain_matches_bare_everyone_case_insensitive():
    assert _trustee_is_domain("everyone") is True


def test_trustee_is_domain_matches_authenticated_users():
    assert _trustee_is_domain("NT AUTHORITY\\Authenticated Users") is True


def test_trustee_is_domain_rejects_administrators():
    assert _trustee_is_domain("DOMAIN\\Administrators") is False


def test_trustee_is_domain_rejects_raw_sid():
    assert _trustee_is_domain("S-1-5-21-1-2-3-1104") is False


def _sec(dacl):
    return {"owner": "DOMAIN\\admin", "group": None, "dacl": dacl}


def test_readable_allow_read_for_domain_users():
    sec = _sec([{"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
                 "rights": ["READ_DATA"], "inherited": True}])
    assert is_domain_readable(sec) is True


def test_readable_generic_read_counts():
    sec = _sec([{"type": "ALLOWED", "trustee": "Everyone",
                 "rights": ["GENERIC_READ"], "inherited": False}])
    assert is_domain_readable(sec) is True


def test_readable_full_control_counts():
    sec = _sec([{"type": "ALLOWED", "trustee": "BUILTIN\\Users",
                 "rights": ["FULL_CONTROL"], "inherited": False}])
    assert is_domain_readable(sec) is True


def test_deny_before_allow_is_not_readable():
    sec = _sec([
        {"type": "DENIED", "trustee": "Everyone",
         "rights": ["READ_DATA"], "inherited": False},
        {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
         "rights": ["READ_DATA"], "inherited": True},
    ])
    assert is_domain_readable(sec) is False


def test_allow_before_deny_is_readable():
    sec = _sec([
        {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
         "rights": ["READ_DATA"], "inherited": False},
        {"type": "DENIED", "trustee": "Everyone",
         "rights": ["READ_DATA"], "inherited": True},
    ])
    assert is_domain_readable(sec) is True


def test_non_read_allow_is_not_readable():
    sec = _sec([{"type": "ALLOWED", "trustee": "Everyone",
                 "rights": ["WRITE_DATA", "APPEND_DATA"], "inherited": False}])
    assert is_domain_readable(sec) is False


def test_trustee_outside_set_is_not_readable():
    sec = _sec([{"type": "ALLOWED", "trustee": "DOMAIN\\Administrators",
                 "rights": ["FULL_CONTROL"], "inherited": False}])
    assert is_domain_readable(sec) is False


def test_deny_for_unrelated_right_does_not_block():
    sec = _sec([
        {"type": "DENIED", "trustee": "Everyone",
         "rights": ["WRITE_DATA"], "inherited": False},
        {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
         "rights": ["READ_DATA"], "inherited": True},
    ])
    assert is_domain_readable(sec) is True


def test_error_security_is_not_readable():
    assert is_domain_readable({"error": "STATUS_ACCESS_DENIED"}) is False


def test_missing_security_is_not_readable():
    assert is_domain_readable(None) is False


def test_empty_dacl_is_not_readable():
    assert is_domain_readable(_sec([])) is False


NEW_SCHEMA = {
    "C$": {
        "": {"security": {"owner": "DOMAIN\\admin", "group": None, "dacl": []}},
        "Users": {"security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
            {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
             "rights": ["READ_DATA"], "inherited": True}]}},
        "Users\\public.txt": {
            "size": "1.0 KB", "ctime_epoch": "2026-01-01 00:00:00",
            "mtime_epoch": "2026-01-01 00:00:00", "atime_epoch": "2026-01-01 00:00:00",
            "security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
                {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
                 "rights": ["READ_DATA", "READ_CONTROL"], "inherited": True}]}},
        "Users\\secret.txt": {
            "size": "2.0 KB", "ctime_epoch": "2026-01-01 00:00:00",
            "mtime_epoch": "2026-01-01 00:00:00", "atime_epoch": "2026-01-01 00:00:00",
            "security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
                {"type": "ALLOWED", "trustee": "DOMAIN\\Administrators",
                 "rights": ["FULL_CONTROL"], "inherited": False}]}},
    }
}


def _write_input(tmp_path, hostname, shares):
    d = tmp_path / "input"
    d.mkdir()
    (d / f"{hostname}.json").write_text(json.dumps(shares))
    return d


def _run_main(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", argv)
    main()
    return capsys.readouterr()


def test_domain_readable_keeps_only_readable_files(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", NEW_SCHEMA)
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--domain-readable", r"\.txt$",
    ])
    assert "public.txt" in out.out
    assert "secret.txt" not in out.out


def test_domain_readable_never_emits_folder_or_root_entries(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", NEW_SCHEMA)
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--domain-readable", ".",
    ])
    assert "host,C$,Users\n" not in out.out
    assert out.out.count("public.txt") == 1


def test_new_schema_without_flag_emits_files_only(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", NEW_SCHEMA)
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", r"\.txt$",
    ])
    assert "public.txt" in out.out
    assert "secret.txt" in out.out
    assert "host,C$,Users\n" not in out.out


def test_old_list_schema_still_works(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", {"C$": ["public.txt", "secret.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", r"\.txt$",
    ])
    assert "public.txt" in out.out
    assert "secret.txt" in out.out


def test_old_list_schema_with_domain_readable_drops_all(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", {"C$": ["public.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--domain-readable", r"\.txt$",
    ])
    assert "public.txt" not in out.out
    assert "lacks ACL data" in out.err
