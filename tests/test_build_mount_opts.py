from types import SimpleNamespace

from spider_parser import build_mount_opts


def test_ntlm_simple():
    args = SimpleNamespace(
        kerberos=False, ccache=None,
        username="alice", password="hunter2",
    )
    env, opts = build_mount_opts(args)
    assert env == ""
    assert opts == "username=alice,password=hunter2"


def test_kerberos_simple():
    args = SimpleNamespace(
        kerberos=True, ccache="USER.ccache",
        username="DOMAIN.COM/USER", password=None,
    )
    env, opts = build_mount_opts(args)
    assert env == "KRB5CCNAME='FILE:USER.ccache'"
    assert opts == "sec=krb5,username=DOMAIN.COM/USER,cruid=$(id -u)"


def test_kerberos_ccache_path_with_space():
    args = SimpleNamespace(
        kerberos=True, ccache="/tmp/my creds/USER.ccache",
        username="USER@DOMAIN.COM", password=None,
    )
    env, opts = build_mount_opts(args)
    # The path must remain inside the FILE: prefix and stay shell-safe.
    assert env == "KRB5CCNAME='FILE:/tmp/my creds/USER.ccache'"
    assert opts == "sec=krb5,username=USER@DOMAIN.COM,cruid=$(id -u)"


def test_ntlm_password_with_comma():
    args = SimpleNamespace(
        kerberos=False, ccache=None,
        username="alice", password="foo,bar",
    )
    env, opts = build_mount_opts(args)
    assert env == ""
    assert opts == "username=alice,password=foo%2Cbar"


def test_kerberos_username_with_comma():
    args = SimpleNamespace(
        kerberos=True, ccache="USER.ccache",
        username="DOM,AIN/USER", password=None,
    )
    env, opts = build_mount_opts(args)
    assert env == "KRB5CCNAME='FILE:USER.ccache'"
    assert opts == "sec=krb5,username=DOM%2CAIN/USER,cruid=$(id -u)"
