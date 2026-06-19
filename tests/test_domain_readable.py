import json
import sys

from spider_parser import _trustee_is_domain


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
