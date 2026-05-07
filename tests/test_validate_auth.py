import argparse
from types import SimpleNamespace

import pytest

from spider_parser import validate_auth


def _args(**overrides):
    base = dict(
        mount=False, acl=False,
        kerberos=False, ccache=None,
        username=None, password=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _parser():
    return argparse.ArgumentParser()


def test_no_mount_no_acl_passes_without_auth():
    # If neither -m nor -a, auth flags are not required.
    validate_auth(_parser(), _args())


def test_kerberos_requires_ccache():
    p = _parser()
    with pytest.raises(SystemExit):
        validate_auth(p, _args(acl=True, kerberos=True, username="USER"))


def test_kerberos_requires_username():
    p = _parser()
    with pytest.raises(SystemExit):
        validate_auth(p, _args(acl=True, kerberos=True, ccache="x.ccache"))


def test_kerberos_acl_passes_with_ccache_and_user():
    validate_auth(
        _parser(),
        _args(acl=True, kerberos=True, ccache="x.ccache", username="USER"),
    )


def test_ntlm_mount_requires_password():
    p = _parser()
    with pytest.raises(SystemExit):
        validate_auth(p, _args(mount=True, username="alice"))


def test_ntlm_mount_requires_username():
    p = _parser()
    with pytest.raises(SystemExit):
        validate_auth(p, _args(mount=True, password="pw"))


def test_ntlm_mount_passes_with_user_and_password():
    validate_auth(
        _parser(),
        _args(mount=True, username="alice", password="pw"),
    )


def test_ntlm_acl_requires_password():
    p = _parser()
    with pytest.raises(SystemExit):
        validate_auth(p, _args(acl=True, username="alice"))


def test_kerberos_with_mount_passes():
    # Kerberos auth is valid for --mount as well, not just --acl.
    validate_auth(
        _parser(),
        _args(mount=True, kerberos=True, ccache="x.ccache", username="USER"),
    )


def test_ntlm_acl_requires_both_username_and_password():
    p = _parser()
    with pytest.raises(SystemExit):
        validate_auth(p, _args(acl=True))
