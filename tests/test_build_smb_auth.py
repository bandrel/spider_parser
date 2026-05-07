from types import SimpleNamespace

from spider_parser import build_smb_auth


def test_ntlm_simple():
    args = SimpleNamespace(
        kerberos=False, ccache=None, domain=None,
        username="alice", password="hunter2",
    )
    assert build_smb_auth(args) == "-U 'alice%hunter2'"


def test_ntlm_password_with_single_quote():
    args = SimpleNamespace(
        kerberos=False, ccache=None, domain=None,
        username="alice", password="he said 'hi'",
    )
    # shlex.quote escapes embedded single quotes via the '\'' pattern.
    assert build_smb_auth(args) == "-U 'alice%he said '\"'\"'hi'\"'\"''"


def test_ntlm_username_with_domain_passthrough():
    args = SimpleNamespace(
        kerberos=False, ccache=None, domain=None,
        username="DOMAIN.COM/USER", password="pw",
    )
    assert build_smb_auth(args) == "-U 'DOMAIN.COM/USER%pw'"


def test_ntlm_with_domain_flag_emits_user_at_domain():
    args = SimpleNamespace(
        kerberos=False, ccache=None, domain="CORP",
        username="alice", password="hunter2",
    )
    assert build_smb_auth(args) == "-U 'alice@CORP%hunter2'"


def test_kerberos_simple():
    args = SimpleNamespace(
        kerberos=True, ccache="USER.ccache", domain=None,
        username="DOMAIN.COM/USER", password=None,
    )
    assert build_smb_auth(args) == (
        "--use-krb5-ccache=USER.ccache -U 'DOMAIN.COM/USER'"
    )


def test_kerberos_ccache_path_with_space():
    args = SimpleNamespace(
        kerberos=True, ccache="/tmp/my creds/USER.ccache", domain=None,
        username="USER@DOMAIN.COM", password=None,
    )
    assert build_smb_auth(args) == (
        "--use-krb5-ccache='/tmp/my creds/USER.ccache' -U 'USER@DOMAIN.COM'"
    )
