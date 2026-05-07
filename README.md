# spider_parser

Parse [NetExec](https://github.com/Pennyw0rth/NetExec) `spider_plus` JSON output and either filter file paths by regex or emit ready-to-paste CIFS mount commands.

## Install

With [uv](https://docs.astral.sh/uv/):

```sh
uv tool install git+https://github.com/bandrel/spider_parser
```

Or from a local clone:

```sh
uv tool install .
```

## Usage

```sh
# Filter spider_plus output for paths matching a regex
spider-parser '\.kdbx$'

# Emit mkdir + mount -t cifs commands for every share
spider-parser -m -u USER -p PASS '.*'

# Mount with Kerberos auth (uses ccache)
spider-parser -m -k -u 'DOMAIN.COM/USER' --ccache /path/to/USER.ccache '.*'

# Custom output directory
spider-parser -d /path/to/spider_plus/ '.*'
```

By default `--dir` is `~/.nxc/modules/nxc_spider_plus/`. The mount form resolves each hostname to an IP for the UNC path while keeping the hostname in the local mount point under `/mnt/`. Share names with spaces, dollar signs, or apostrophes are properly shell-escaped.

### Audit DACLs

```sh
# Emit DACL audit commands (smbcacls + rpcclient netsharegetinfo)
spider-parser -a -u USER -p PASS '.*'

# DACL audit with Kerberos
spider-parser -a -k -u 'DOMAIN.COM/USER' --ccache /path/to/USER.ccache '.*'
```

For each matched share, emits a `smbcacls` command (NTFS DACL layer) and a `rpcclient netsharegetinfo ... 502` command (SMB share-level perms). May be combined with `-m` to emit both blocks.

## Version history

### v0.2.0
- Added `-a/--acl` mode to emit DACL audit commands (`smbcacls` + `rpcclient netsharegetinfo`) per matched share
- Added Kerberos auth via `-k/--kerberos` and `--ccache` (works with both `--mount` and `--acl`)
- Mount/ACL auth flag validation: NTLM requires `-u`+`-p`; Kerberos requires `-u`+`--ccache`

### v0.1.1
- Renamed `sp.py` to `spider_parser.py`
- Added built-in regex presets (`-P`, `--list-presets`, `-y/--yolo`)
- Added exclusion file support (`-e/--exclude`)
- Added host filters: `-H/--host` (include) and `--exclude-host` (substring, case-insensitive)
- Skip `SYSVOL` by default; opt back in with `--include-sysvol`
- Skip files with invalid JSON instead of reusing stale parser state
