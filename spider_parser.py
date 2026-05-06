#!/usr/bin/env python3.9


import glob
import json
import os
import re
import shlex
import socket
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
}


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


def main():
    parser = argparse.ArgumentParser(description='', epilog=f'Available presets: {", ".join(PRESETS.keys())}')
    parser.add_argument('-d','--dir', type=str, default=os.path.expanduser('~/.nxc/modules/nxc_spider_plus/'), help='Directory of nxc spider_plus output. Default is ~/.nxc/modules/nxc_spider_plus/')
    parser.add_argument('REGEX', type=str, nargs='?', help='Regex pattern or preset name to search for')
    parser.add_argument('-P', '--presets', type=str, help='Comma-separated preset names or path to JSON file containing presets')

    parser.add_argument('-m','--mount',default=False, action=argparse.BooleanOptionalAction, help='Display commands necessary to create mount shares')
    parser.add_argument('-u','--username', help='Username for mount')
    parser.add_argument('-p','--password', help='password for mount')
    parser.add_argument('--include-sysvol', default=False, action='store_true', help='Include SYSVOL share (ignored by default)')
    parser.add_argument('--list-presets', action='store_true', help='List all available regex presets')
    parser.add_argument('-y','--yolo', action='store_true', help='Run all built-in presets (yolo mode)')
    parser.add_argument('-e','--exclude', type=str, help='Path to exclusion file (format: hostname or hostname,share per line)')
    parser.add_argument('-H','--host', type=str, action='append', help='Only include specific host(s). Can be used multiple times')
    args = parser.parse_args()

    if args.list_presets:
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

        if hostname in exclusions['hosts']:
            continue

        with open(file_path) as open_file:
            try:
                a = json.load(open_file)
            except json.decoder.JSONDecodeError:
                pass
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
    if args.mount:
        host_ip_cache = {}
        for hostname, share in sorted(matched_shares):
            if hostname not in host_ip_cache:
                try:
                    host_ip_cache[hostname] = socket.gethostbyname(hostname)
                except socket.gaierror:
                    print(f'# DNS lookup failed for {hostname}, skipping', file=sys.stderr)
                    host_ip_cache[hostname] = None
            ip = host_ip_cache[hostname]
            if ip is None:
                continue
            unc = f'//{ip}/{share}'
            mount_point = f'/mnt/{hostname}/{share}'
            opts = f'username={args.username},password={args.password}'
            print(f'mkdir -p {shlex.quote(mount_point)}')
            print(f'mount -t cifs {shlex.quote(unc)} {shlex.quote(mount_point)} -o {shlex.quote(opts)}')


if __name__ == '__main__':
    main()
