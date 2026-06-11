#!/usr/bin/env python3.9


import glob
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import argparse

# Preset regex patterns
PRESETS = {
    'passwords': r'password|passwd|pwd|pass\.txt|credentials|creds|secret',
    'configs': r'\.config|\.conf|\.ini|\.xml|\.yaml|\.yml|settings',
    'keys': r'\.key|\.pem|\.pfx|\.p12|\.crt|\.cer|id_rsa|private',
    'scripts': r'\.ps1|\.bat|\.cmd|\.vbs|\.sh',
    'sensitive': r'password|secret|key|token|api|credential|private|confidential',
    'database': r'\.sql|\.db|\.mdb|\.accdb|\.sqlite|\.csv|database|backup\.bak',
    'backup': r'\.bak|\.backup|\.old|\.tmp|\.swp|\.csv|~',
    'code': r'\.py|\.java|\.cpp|\.c|\.cs|\.js|\.php|\.rb|\.go',
    'documents': r'\.doc|\.docx|\.xls|\.xlsx|\.pdf|\.txt|\.rtf|\.odt',
    'web': r'\.html|\.htm|\.asp|\.aspx|\.jsp|\.php',
    'financial': r'invoice|receipt|payment|budget|financial|accounting|payroll|salary|tax|revenue|expense|profit|loss|balance|statement|quickbooks|\.qb[owx]|sage|xero',
    'virtualdisks': r'\.vmdk|\.vhdx?|\.vdi|\.qcow2?|\.ova|\.ovf|\.hdd|\.pvm|\.vbox|\.img|\.iso|\.avhdx?',
}


def _sq(s):
    """Shell-quote: always wrap in single quotes, escaping any embedded single quotes."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def build_smb_auth(args):
    """Build the auth-string fragment used by smbcacls and rpcclient.

    Kerberos: --use-krb5-ccache=<PATH> -U '<USER>'
    NTLM:     -U '<USER>[@<DOMAIN>]%<PASS>'
    """
    if args.kerberos:
        ccache_part = f"--use-krb5-ccache={shlex.quote(args.ccache)}"
        return f"{ccache_part} -U {_sq(args.username)}"
    user_part = f"{args.username}@{args.domain}" if args.domain else args.username
    return f"-U {_sq(f'{user_part}%{args.password}')}"


def _mount_val(s):
    """Escape characters that are special in mount -o opt=val,opt=val strings."""
    return s.replace(",", "%2C")


def build_mount_opts(args):
    """Build (env_prefix, opts_string) for the mount -t cifs command.

    NTLM:     ("", "username=<U>,password=<P>")
    Kerberos: ("KRB5CCNAME='FILE:<PATH>'",
               "sec=krb5,username=<U>,cruid=$(id -u)")

    Returns ("", opts) when no env prefix is needed; callers must check
    `if env:` before prepending it to the mount command.

    Commas in username/password are percent-encoded so they don't get
    parsed as -o option separators by mount.cifs.
    """
    if args.kerberos:
        env = f"KRB5CCNAME={_sq(f'FILE:{args.ccache}')}"
        opts = f"sec=krb5,username={_mount_val(args.username)},cruid=$(id -u)"
        return env, opts
    return "", f"username={_mount_val(args.username)},password={_mount_val(args.password)}"


def validate_auth(parser, args):
    """Verify required auth flags for the active modes.

    Safe to call unconditionally; returns immediately when neither
    --mount nor --acl is active.
    """
    if not (args.mount or args.acl):
        return
    if args.kerberos:
        missing = []
        if not args.ccache:
            missing.append("--ccache")
        if not args.username:
            missing.append("-u/--username")
        if missing:
            parser.error(
                "Kerberos auth requires: " + ", ".join(missing)
            )
        return
    # NTLM mode.
    missing = []
    if not args.username:
        missing.append("-u/--username")
    if not args.password:
        missing.append("-p/--password")
    if missing:
        parser.error("NTLM auth requires: " + ", ".join(missing))


def load_exclusions(exclude_file):
    """Load exclusion list from file. Format: hostname or hostname,share (one per line)"""
    exclusions = {'hosts': set(), 'shares': set()}
    try:
        with open(exclude_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ',' in line:
                        host, share = line.split(',', 1)
                        exclusions['shares'].add((host.strip(), share.strip()))
                    else:
                        exclusions['hosts'].add(line)
    except FileNotFoundError:
        pass
    return exclusions


def run_or_print(cmd, do_exec):
    """Print a shell command, optionally executing it under shell=True.

    Fail-fast: if do_exec is True and the command exits non-zero, write a
    marker to stderr and sys.exit() with the same return code. Output is
    not captured — the child inherits the parent terminal.
    """
    print(cmd, flush=True)
    if not do_exec:
        return
    rc = subprocess.run(cmd, shell=True).returncode
    if rc != 0:
        print(f"# ERROR: command failed (exit {rc}): {cmd}", file=sys.stderr)
        sys.exit(rc)


def main():
    parser = argparse.ArgumentParser(description='', epilog=f'Available presets: {", ".join(PRESETS.keys())}')
    parser.add_argument('-d','--dir', type=str, default=os.path.expanduser('~/.nxc/modules/nxc_spider_plus/'), help='Directory of nxc spider_plus output. Default is ~/.nxc/modules/nxc_spider_plus/')
    parser.add_argument('REGEX', type=str, nargs='?', help='Regex pattern or preset name to search for')
    parser.add_argument('-P', '--presets', type=str, nargs='?', const='', default=None, help='Comma-separated preset names or path to JSON file containing presets. Pass without a value to list available presets.')

    parser.add_argument('-m','--mount',default=False, action=argparse.BooleanOptionalAction, help='Display commands necessary to create mount shares')
    parser.add_argument('-a','--acl',default=False, action=argparse.BooleanOptionalAction, help='Display commands to audit DACLs (smbcacls)')
    exec_group = parser.add_mutually_exclusive_group()
    exec_group.add_argument('--exec', default=False, action='store_true', help='Execute each emitted command via subprocess (fail-fast on non-zero exit)')
    exec_group.add_argument('--dry-run', default=False, action='store_true', help='Print only; explicit no-op form of the default behavior (mutually exclusive with --exec)')
    parser.add_argument('-u','--username', help='Username for mount/acl auth (passed verbatim into -U)')
    parser.add_argument('-p','--password', help='Password for NTLM auth (mount/acl)')
    parser.add_argument('-D','--domain', help='Domain for NTLM auth; produces -U user@domain%%password (mount/acl)')
    parser.add_argument('-k','--kerberos', default=False, action='store_true', help='Use Kerberos auth (requires --ccache and -u)')
    parser.add_argument('--ccache', help='Path to Kerberos credential cache file (used with -k for --mount and --acl)')
    parser.add_argument('--include-sysvol', default=False, action='store_true', help='Include SYSVOL share (ignored by default)')
    parser.add_argument('--list-presets', action='store_true', help='List all available regex presets')
    parser.add_argument('-y','--yolo', action='store_true', help='Run all built-in presets (yolo mode)')
    parser.add_argument('-e','--exclude', type=str, help='Path to exclusion file (format: hostname or hostname,share per line)')
    parser.add_argument('-H','--host', type=str, action='append', help='Only include specific host(s). Can be used multiple times')
    parser.add_argument('--exclude-host', type=str, action='append', default=[], help='Exclude files whose name contains this substring (case-insensitive). Can be used multiple times.')
    args = parser.parse_args()
    validate_auth(parser, args)
    if args.exec and not (args.mount or args.acl):
        parser.error("--exec requires --mount or --acl")

    if args.list_presets or args.presets == '':
        print("Available regex presets:")
        for name, pattern in sorted(PRESETS.items()):
            print(f"  {name:15} - {pattern}")
        sys.exit(0)

    if not args.REGEX and not args.presets and not args.yolo:
        parser.error("Either REGEX, --presets, or --yolo is required")

    exclusions = {'hosts': set(), 'shares': set()}
    if args.exclude:
        exclusions = load_exclusions(args.exclude)

    #list all files in directory
    files = glob.glob(args.dir+'*.json')

    # Build list of (label, compiled_pattern). If presets are provided, use them;
    # otherwise fall back to the single REGEX argument.
    pattern_items = []

    if args.yolo:
        for name, pat in PRESETS.items():
            pattern_items.append((name, re.compile(pat, re.IGNORECASE)))

    elif args.presets:
        presets_arg = args.presets
        if os.path.exists(presets_arg):
            try:
                with open(presets_arg, 'r') as pf:
                    preset_obj = json.load(pf)
            except Exception:
                parser.error(f'Unable to load presets from {presets_arg}')

            if isinstance(preset_obj, dict):
                for name, pat in preset_obj.items():
                    pattern_items.append((name, re.compile(pat, re.IGNORECASE)))
            elif isinstance(preset_obj, list):
                for idx, pat in enumerate(preset_obj, start=1):
                    label = f'preset{idx}'
                    pattern_items.append((label, re.compile(pat, re.IGNORECASE)))
            else:
                parser.error('Presets JSON must be an object or list')
        else:
            for name in [n.strip() for n in presets_arg.split(',') if n.strip()]:
                if name in PRESETS:
                    pattern_items.append((name, re.compile(PRESETS[name], re.IGNORECASE)))
                else:
                    parser.error(f'Unknown preset name: {name}')

    else:
        if args.REGEX in PRESETS:
            pattern_items.append((args.REGEX, re.compile(PRESETS[args.REGEX], re.IGNORECASE)))
        else:
            pattern_items.append((None, re.compile(args.REGEX)))

    # Track shares with matches for mount command generation
    matched_shares = set()

    for file_path in files:
        file = file_path.split('/')[-1:][0]
        hostname = '.'.join(file.split('.')[:-1])

        if args.host and hostname not in args.host:
            continue

        if args.exclude_host and any(s.lower() in hostname.lower() for s in args.exclude_host):
            continue

        if hostname in exclusions['hosts']:
            continue

        with open(file_path) as open_file:
            try:
                a = json.load(open_file)
            except json.decoder.JSONDecodeError:
                print(f'# Skipping {file_path}: invalid JSON', file=sys.stderr)
                continue
            for key in a.keys():
                if (hostname, key) in exclusions['shares']:
                    continue
                #If share is IPC$ we can skip it, also skip SYSVOL unless --include-sysvol is set
                if key != 'IPC$' and (args.include_sysvol or key != 'SYSVOL'):
                    #if share is not IPC$ then iterate through the items in the share.
                    for item in a[key]:
                        for label, compiled in pattern_items:
                            if compiled.search(item):
                                if label:
                                    print(f'{hostname},{key},{label},{item}')
                                else:
                                    print(f'{hostname},{key},{item}')
                                matched_shares.add((hostname, key))
                                break
    host_ip_cache = {}

    def _resolve(hostname):
        if hostname not in host_ip_cache:
            try:
                host_ip_cache[hostname] = socket.gethostbyname(hostname)
            except socket.gaierror:
                print(f'# DNS lookup failed for {hostname}, skipping', file=sys.stderr)
                host_ip_cache[hostname] = None
        return host_ip_cache[hostname]

    mount_emitted = False
    if args.mount:
        env, opts = build_mount_opts(args)
        for hostname, share in sorted(matched_shares):
            ip = _resolve(hostname)
            if ip is None:
                continue
            unc = f'//{ip}/{share}'
            mount_point = f'/mnt/{hostname}/{share}'
            run_or_print(f'mkdir -p {shlex.quote(mount_point)}', args.exec)
            mount_cmd = f'mount -t cifs {shlex.quote(unc)} {shlex.quote(mount_point)} -o {shlex.quote(opts)}'
            if env:
                mount_cmd = f'{env} {mount_cmd}'
            run_or_print(mount_cmd, args.exec)
            mount_emitted = True

    if args.acl:
        if mount_emitted:
            print()
        auth = build_smb_auth(args)
        for hostname, share in sorted(matched_shares):
            ip = _resolve(hostname)
            if ip is None:
                continue
            unc = f'//{ip}/{share}'
            print(f'# {hostname} / {share} \u2014 DACL audit')
            run_or_print(f"smbcacls {shlex.quote(unc)} '/' {auth}", args.exec)


if __name__ == '__main__':
    main()
