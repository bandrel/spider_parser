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

# Execute every emitted command (mount typically needs root)
sudo spider-parser -m --exec -u USER -p PASS '.*'

# Custom output directory
spider-parser -d /path/to/spider_plus/ '.*'
```

By default `--dir` is `~/.nxc/modules/nxc_spider_plus/`. The mount form resolves each hostname to an IP for the UNC path while keeping the hostname in the local mount point under `/mnt/`. Share names with spaces, dollar signs, or apostrophes are properly shell-escaped.

### Audit DACLs

```sh
# Emit smbcacls DACL audit commands
spider-parser -a -u USER -p PASS '.*'

# With NTLM domain (-U user@domain%password format)
spider-parser -a -u USER -p PASS -D CORP '.*'

# DACL audit with Kerberos
spider-parser -a -k -u 'DOMAIN.COM/USER' --ccache /path/to/USER.ccache '.*'

# Execute the smbcacls commands directly
spider-parser -a --exec -u USER -p PASS '.*'
```

For each matched share, emits a `smbcacls` command (NTFS DACL layer). May be combined with `-m` to emit both blocks. Pass `--exec` to run each emitted command (fail-fast on first non-zero exit) or `--dry-run` for an explicit print-only mode (default behavior).

## Version history

### v0.3.3
- Added `--include-dll` to include files ending in `.dll` (excluded by default, like `--include-sysvol`)
- Anchored all preset file-extension patterns with `$` so they only match at the end of a filename (fixes false positives like `\.iso` matching `Microsoft.IsolatedStorage.dll`)
- Pattern matching now runs against the file basename only, so directory names in the path no longer trigger keyword/extension matches

### v0.3.2
- Added `virtualdisks` preset matching virtual hard drive / disk image extensions (`.vmdk`, `.vhd`, `.vhdx`, `.avhd(x)`, `.vdi`, `.vbox`, `.qcow`, `.qcow2`, `.ova`, `.ovf`, `.hdd`, `.pvm`, `.img`, `.iso`)

### v0.3.1
- `-P/--presets` with no argument now lists available presets instead of erroring (equivalent to `--list-presets`)

### v0.3.0
- Added `--exec` to run emitted `mount`/`smbcacls` commands directly (fail-fast on first non-zero exit, output streams live)
- Added `--dry-run` as an explicit print-only form (mutually exclusive with `--exec`)

### v0.2.1
- Added `-D/--domain` for NTLM auth (`-U user@domain%password` format)
- Dropped `rpcclient netsharegetinfo` line from `--acl` output (level 502 requires admin and returned `WERR_ACCESS_DENIED` for typical users; `smbcacls` covers the audit need)

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
