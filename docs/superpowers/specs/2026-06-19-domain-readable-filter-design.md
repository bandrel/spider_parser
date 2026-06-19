# Design: `--domain-readable` filter

Date: 2026-06-19
Status: Approved

## Goal

Add a `--domain-readable` flag to `spider_parser.py` that suppresses output lines
for files a normal domain user could **not** read, based on the per-file ACL data
in the new `nxc spider_plus` JSON schema (NetExec branch `feature/spider-plus-acl`).

## Background: schema change

The updated `spider_plus` module changes the JSON output shape.

**Old schema** — `share` maps to a **list** of file-path strings:

```json
{ "C$": ["Users\\admin\\secret.txt", "Windows\\notes.txt"] }
```

**New schema** — `share` maps to a **dict** of `path -> metadata`. File entries carry
`size`/`*time` fields; folder and share-root (`""`) entries carry only a `security`
block; every entry may carry a `security` block when SD reads are enabled:

```json
{
  "C$": {
    "": { "security": { "owner": "...", "group": "...", "dacl": [] } },
    "Users": { "security": { "...": "..." } },
    "Users\\admin\\secret.txt": {
      "size": "1.2 KB",
      "ctime_epoch": "2026-01-01 00:00:00",
      "mtime_epoch": "2026-01-01 00:00:00",
      "atime_epoch": "2026-01-01 00:00:00",
      "security": {
        "owner": "DOMAIN\\admin",
        "group": "DOMAIN\\Domain Users",
        "dacl": [
          { "type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
            "rights": ["READ_DATA", "READ_CONTROL"], "inherited": true },
          { "type": "DENIED", "trustee": "Everyone",
            "rights": ["WRITE_DATA"], "inherited": false }
        ]
      }
    }
  }
}
```

`security` may instead be `{"error": "STATUS_ACCESS_DENIED"}` (or `"unknown"`) when the
SD could not be read. `dacl` is `[]` when no DACL is present.

ACE `rights` values come from `decode_file_access_mask`: file-specific right names
(`READ_DATA`, `WRITE_DATA`, ...), generic names (`GENERIC_READ`, `GENERIC_ALL`, ...),
the collapsed `FULL_CONTROL`, or a raw `0x...` hex string when no bits are recognized.
ACE `trustee` is a resolved name (`DOMAIN\\Domain Users`, `BUILTIN\\Users`, `Everyone`)
or a raw SID string when resolution failed. DACL order is preserved from the SD.

## Flag

`--domain-readable` (`store_true`, default `False`). An **additive** filter: it
composes with whatever matching is already active (`REGEX`, `-P/--presets`, `-y/--yolo`)
and does not change the output line format. It only suppresses lines whose backing file
is not domain-readable.

## Schema handling (backward compatible)

The per-share iteration must handle both shapes:

- `a[share]` is a **list** (old schema): iterate path strings exactly as today. There is
  no ACL data, so when `--domain-readable` is set every entry is treated as
  not-determinable and suppressed; emit a single `stderr` note per run that the input
  lacks ACL data (so an empty result is not mistaken for "nothing matched").
- `a[share]` is a **dict** (new schema): iterate `(path, meta)` items. Skip the `""`
  root entry and any entry whose `meta` lacks a `"size"` key (those are folder/dir SD
  records, not files) so output stays file-only, matching current behavior. When
  `--domain-readable` is unset, behavior is otherwise identical to the list path
  (match basenames, emit matching files).

The existing basename-matching, `.dll` skip, `--include-sysvol`, host/share exclusion,
and `matched_shares` tracking all continue to apply to file entries in both schemas.

## Readability test (Windows access-check faithful)

`is_domain_readable(security) -> bool`, applied only when `--domain-readable` is set.

Model the caller as a principal holding **all** of these group memberships at once:

- `Domain Users`     (matches resolved trustee ending in `\Domain Users`, case-insensitive)
- `Authenticated Users`
- `Everyone`
- `Users`            (`BUILTIN\Users`)

Trustee matching is case-insensitive and tolerant of `DOMAIN\` / `BUILTIN\` prefixes:
strip any prefix up to and including the last `\`, then compare the remainder to the
group name set. Read-relevant rights: `{READ_DATA, GENERIC_READ, GENERIC_ALL,
FULL_CONTROL}`.

Algorithm (mirrors how Windows resolves an open-for-read against a DACL):

1. If `security` is falsy, contains an `"error"` key, or has no non-empty `dacl`
   → return `False` (cannot prove readable).
2. Walk `security["dacl"]` **in stored order**. For each ACE:
   - Skip if its trustee is not one of the domain trustees.
   - Skip if none of its `rights` is read-relevant.
   - Otherwise this is the deciding ACE: return `False` if `type == "DENIED"`,
     `True` if `type == "ALLOWED"`.
3. If no deciding ACE is found → return `False`.

Because evaluation is order-sensitive, a DENY only wins when it precedes the grant — an
explicit ALLOW ordered ahead of an inherited DENY (the canonical SD ordering) grants
access, exactly as Windows would.

## Components

- `DOMAIN_TRUSTEES` (frozenset of lowercased group names) and `READ_RIGHTS` (frozenset)
  module constants.
- `_trustee_is_domain(trustee: str) -> bool` helper (prefix-strip + membership test).
- `is_domain_readable(security) -> bool` pure function (the algorithm above).
- Integration in `main`'s per-file emission loop: when `args.domain_readable` and the
  entry fails `is_domain_readable`, `continue` before matching/printing.

## Testing

New `tests/test_domain_readable.py`:

- `is_domain_readable`: allowed read for each domain trustee; deny-before-allow ⇒ False;
  allow-before-deny ⇒ True; `GENERIC_READ` / `FULL_CONTROL` count; non-read allow (e.g.
  `WRITE_DATA` only) ⇒ False; trustee outside the set ⇒ False; `{"error": ...}` ⇒ False;
  missing `security` ⇒ False; empty `dacl` ⇒ False; case/prefix variants of trustee.
- End-to-end: write a new-schema JSON fixture to a temp dir, run `main` with
  `--domain-readable` + a preset/regex, assert only domain-readable files are printed and
  folder/root entries are never emitted.
- Regression: old list-schema JSON still parses and emits as before when
  `--domain-readable` is unset.

## Docs / version

- README: document `--domain-readable` under options, noting it requires the ACL-aware
  `spider_plus` output and drops files whose readability cannot be proven.
- Bump version `0.3.3` → `0.4.0` in `pyproject.toml` and `spider_parser.py` if a version
  string is present there.

## Non-goals

- No new output format / no per-file ACL printing (matching behavior only).
- No write-access or owner-based filtering.
- No change to mount/acl command generation.
