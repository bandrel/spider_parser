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

# Custom output directory
spider-parser -d /path/to/spider_plus/ '.*'
```

By default `--dir` is `~/.nxc/modules/nxc_spider_plus/`. The mount form resolves each hostname to an IP for the UNC path while keeping the hostname in the local mount point under `/mnt/`. Share names with spaces, dollar signs, or apostrophes are properly shell-escaped.

## Version history

### v0.1.1
- Renamed `sp.py` to `spider_parser.py`
- Added built-in regex presets (`-P`, `--list-presets`, `-y/--yolo`)
- Added exclusion file support (`-e/--exclude`)
- Added host filters: `-H/--host` (include) and `--exclude-host` (substring, case-insensitive)
- Skip `SYSVOL` by default; opt back in with `--include-sysvol`
- Skip files with invalid JSON instead of reusing stale parser state
