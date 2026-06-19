# `--domain-readable` Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--domain-readable` flag that suppresses output for files a normal domain user could not read, using the ACL data in the new `nxc spider_plus` JSON schema.

**Architecture:** Two pure helpers (`_trustee_is_domain`, `is_domain_readable`) plus module constants implement a Windows-faithful, order-sensitive DACL read check. `main`'s per-file loop is reworked to handle both the old list schema and the new dict schema, and to skip non-readable files when the flag is set.

**Tech Stack:** Python 3.9+, argparse, pytest. No new dependencies.

Spec: `docs/superpowers/specs/2026-06-19-domain-readable-filter-design.md`

---

## File Structure

- Modify: `spider_parser.py` — add constants + helpers near the top (after `PRESETS`); add the argparse flag; rework the per-file emission loop.
- Create: `tests/test_domain_readable.py` — unit tests for the helpers + end-to-end + regression.
- Modify: `README.md` — document the flag.
- Modify: `pyproject.toml` — bump version to `0.4.0`.

The new-schema fixture used by several tests (define once per test as a local literal):

```python
NEW_SCHEMA = {
    "C$": {
        "": {"security": {"owner": "DOMAIN\\admin", "group": None, "dacl": []}},
        "Users": {"security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
            {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
             "rights": ["READ_DATA"], "inherited": True}]}},
        "Users\\public.txt": {
            "size": "1.0 KB", "ctime_epoch": "2026-01-01 00:00:00",
            "mtime_epoch": "2026-01-01 00:00:00", "atime_epoch": "2026-01-01 00:00:00",
            "security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
                {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
                 "rights": ["READ_DATA", "READ_CONTROL"], "inherited": True}]}},
        "Users\\secret.txt": {
            "size": "2.0 KB", "ctime_epoch": "2026-01-01 00:00:00",
            "mtime_epoch": "2026-01-01 00:00:00", "atime_epoch": "2026-01-01 00:00:00",
            "security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
                {"type": "ALLOWED", "trustee": "DOMAIN\\Administrators",
                 "rights": ["FULL_CONTROL"], "inherited": False}]}},
    }
}
```

---

### Task 1: Module constants and `_trustee_is_domain`

**Files:**
- Modify: `spider_parser.py` (insert after the `PRESETS` dict, before `_sq`)
- Test: `tests/test_domain_readable.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_domain_readable.py`:

```python
import json
import sys

from spider_parser import _trustee_is_domain, is_domain_readable, main


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_domain_readable.py -k trustee -v`
Expected: FAIL with `ImportError: cannot import name '_trustee_is_domain'`

- [ ] **Step 3: Write minimal implementation**

Insert into `spider_parser.py` after the `PRESETS` dict (line ~28):

```python
# Trustees a normal domain user effectively holds, for --domain-readable.
# Compared against the resolved ACE trustee name with any DOMAIN\ / BUILTIN\
# prefix stripped, lowercased.
DOMAIN_TRUSTEES = frozenset({
    'domain users',
    'authenticated users',
    'everyone',
    'users',
})

# Rights that grant read access to a file's data.
READ_RIGHTS = frozenset({
    'READ_DATA',
    'GENERIC_READ',
    'GENERIC_ALL',
    'FULL_CONTROL',
})


def _trustee_is_domain(trustee):
    """True if a resolved ACE trustee is one of the broad domain-user groups.

    Strips any prefix up to and including the last backslash (DOMAIN\\, BUILTIN\\)
    and compares the remainder case-insensitively against DOMAIN_TRUSTEES.
    """
    if not trustee:
        return False
    name = trustee.rsplit('\\', 1)[-1].strip().lower()
    return name in DOMAIN_TRUSTEES
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_domain_readable.py -k trustee -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add spider_parser.py tests/test_domain_readable.py
git commit -m "Add DOMAIN_TRUSTEES/READ_RIGHTS constants and _trustee_is_domain"
```

---

### Task 2: `is_domain_readable`

**Files:**
- Modify: `spider_parser.py` (immediately after `_trustee_is_domain`)
- Test: `tests/test_domain_readable.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_domain_readable.py`:

```python
def _sec(dacl):
    return {"owner": "DOMAIN\\admin", "group": None, "dacl": dacl}


def test_readable_allow_read_for_domain_users():
    sec = _sec([{"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
                 "rights": ["READ_DATA"], "inherited": True}])
    assert is_domain_readable(sec) is True


def test_readable_generic_read_counts():
    sec = _sec([{"type": "ALLOWED", "trustee": "Everyone",
                 "rights": ["GENERIC_READ"], "inherited": False}])
    assert is_domain_readable(sec) is True


def test_readable_full_control_counts():
    sec = _sec([{"type": "ALLOWED", "trustee": "BUILTIN\\Users",
                 "rights": ["FULL_CONTROL"], "inherited": False}])
    assert is_domain_readable(sec) is True


def test_deny_before_allow_is_not_readable():
    sec = _sec([
        {"type": "DENIED", "trustee": "Everyone",
         "rights": ["READ_DATA"], "inherited": False},
        {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
         "rights": ["READ_DATA"], "inherited": True},
    ])
    assert is_domain_readable(sec) is False


def test_allow_before_deny_is_readable():
    sec = _sec([
        {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
         "rights": ["READ_DATA"], "inherited": False},
        {"type": "DENIED", "trustee": "Everyone",
         "rights": ["READ_DATA"], "inherited": True},
    ])
    assert is_domain_readable(sec) is True


def test_non_read_allow_is_not_readable():
    sec = _sec([{"type": "ALLOWED", "trustee": "Everyone",
                 "rights": ["WRITE_DATA", "APPEND_DATA"], "inherited": False}])
    assert is_domain_readable(sec) is False


def test_trustee_outside_set_is_not_readable():
    sec = _sec([{"type": "ALLOWED", "trustee": "DOMAIN\\Administrators",
                 "rights": ["FULL_CONTROL"], "inherited": False}])
    assert is_domain_readable(sec) is False


def test_deny_for_unrelated_right_does_not_block():
    sec = _sec([
        {"type": "DENIED", "trustee": "Everyone",
         "rights": ["WRITE_DATA"], "inherited": False},
        {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
         "rights": ["READ_DATA"], "inherited": True},
    ])
    assert is_domain_readable(sec) is True


def test_error_security_is_not_readable():
    assert is_domain_readable({"error": "STATUS_ACCESS_DENIED"}) is False


def test_missing_security_is_not_readable():
    assert is_domain_readable(None) is False


def test_empty_dacl_is_not_readable():
    assert is_domain_readable(_sec([])) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_domain_readable.py -k "readable or deny or allow or error or missing or empty or non_read or trustee_outside" -v`
Expected: FAIL with `ImportError: cannot import name 'is_domain_readable'`

- [ ] **Step 3: Write minimal implementation**

Insert into `spider_parser.py` immediately after `_trustee_is_domain`:

```python
def is_domain_readable(security):
    """True if a normal domain user could read the file, per its serialized SD.

    Mirrors the Windows DACL access check for an open-for-read: the caller is
    modeled as holding all DOMAIN_TRUSTEES memberships at once, and the DACL is
    walked in stored order. The first ACE that targets one of those trustees and
    carries a read-relevant right decides: DENIED -> not readable, ALLOWED ->
    readable. Missing/error/no-DACL security is treated as not provably readable.
    """
    if not security or 'error' in security:
        return False
    dacl = security.get('dacl')
    if not dacl:
        return False
    for ace in dacl:
        if not _trustee_is_domain(ace.get('trustee')):
            continue
        if not any(r in READ_RIGHTS for r in ace.get('rights', [])):
            continue
        return ace.get('type') == 'ALLOWED'
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_domain_readable.py -v`
Expected: PASS (all tests; helpers from Task 1 still pass)

- [ ] **Step 5: Commit**

```bash
git add spider_parser.py tests/test_domain_readable.py
git commit -m "Add is_domain_readable Windows-faithful DACL read check"
```

---

### Task 3: Add the `--domain-readable` argparse flag

**Files:**
- Modify: `spider_parser.py` (in `main`, near the other `--include-*` flags, ~line 154)

- [ ] **Step 1: Add the flag**

In `main`, immediately after the `--include-dll` argument (line ~154), add:

```python
    parser.add_argument('--domain-readable', default=False, action='store_true', help='Only output files readable by a normal domain user (requires ACL-aware spider_plus output; files without ACL data are dropped)')
```

- [ ] **Step 2: Verify it parses**

Run: `python spider_parser.py --domain-readable . -d /tmp/nonexistent/ ; echo "exit=$?"`
Expected: no argparse error about an unknown flag (exit 0; an empty glob simply prints nothing).

- [ ] **Step 3: Commit**

```bash
git add spider_parser.py
git commit -m "Add --domain-readable argparse flag"
```

---

### Task 4: Rework the per-file loop for dict/list schema + readable filter

**Files:**
- Modify: `spider_parser.py` (the `for key in a.keys():` block, lines ~242-263)
- Test: `tests/test_domain_readable.py`

This task replaces the inner share-iteration body so it handles both schemas and
applies the readable filter. The current code (for reference) is:

```python
            for key in a.keys():
                if (hostname, key) in exclusions['shares']:
                    continue
                if key != 'IPC$' and (args.include_sysvol or key != 'SYSVOL'):
                    for item in a[key]:
                        name = re.split(r'[\\/]', item)[-1]
                        if not args.include_dll and name.lower().endswith('.dll'):
                            continue
                        for label, compiled in pattern_items:
                            if compiled.search(name):
                                if label:
                                    print(f'{hostname},{key},{label},{item}')
                                else:
                                    print(f'{hostname},{key},{item}')
                                matched_shares.add((hostname, key))
                                break
```

- [ ] **Step 1: Write the failing end-to-end + regression tests**

Append to `tests/test_domain_readable.py` (NEW_SCHEMA literal from the File
Structure section above — paste it near the top of the file once):

```python
NEW_SCHEMA = {
    "C$": {
        "": {"security": {"owner": "DOMAIN\\admin", "group": None, "dacl": []}},
        "Users": {"security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
            {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
             "rights": ["READ_DATA"], "inherited": True}]}},
        "Users\\public.txt": {
            "size": "1.0 KB", "ctime_epoch": "2026-01-01 00:00:00",
            "mtime_epoch": "2026-01-01 00:00:00", "atime_epoch": "2026-01-01 00:00:00",
            "security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
                {"type": "ALLOWED", "trustee": "DOMAIN\\Domain Users",
                 "rights": ["READ_DATA", "READ_CONTROL"], "inherited": True}]}},
        "Users\\secret.txt": {
            "size": "2.0 KB", "ctime_epoch": "2026-01-01 00:00:00",
            "mtime_epoch": "2026-01-01 00:00:00", "atime_epoch": "2026-01-01 00:00:00",
            "security": {"owner": "DOMAIN\\admin", "group": None, "dacl": [
                {"type": "ALLOWED", "trustee": "DOMAIN\\Administrators",
                 "rights": ["FULL_CONTROL"], "inherited": False}]}},
    }
}


def _write_input(tmp_path, hostname, shares):
    d = tmp_path / "input"
    d.mkdir()
    (d / f"{hostname}.json").write_text(json.dumps(shares))
    return d


def _run_main(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", argv)
    main()
    return capsys.readouterr()


def test_domain_readable_keeps_only_readable_files(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", NEW_SCHEMA)
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--domain-readable", r"\.txt$",
    ])
    assert "public.txt" in out.out
    assert "secret.txt" not in out.out


def test_domain_readable_never_emits_folder_or_root_entries(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", NEW_SCHEMA)
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--domain-readable", ".",
    ])
    # "Users" folder entry and "" root carry only a security block, no size.
    assert "host,C$,Users\n" not in out.out
    assert out.out.count("public.txt") == 1


def test_new_schema_without_flag_emits_files_only(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", NEW_SCHEMA)
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", r"\.txt$",
    ])
    assert "public.txt" in out.out
    assert "secret.txt" in out.out          # no filter -> both files
    assert "host,C$,Users\n" not in out.out  # folder record still skipped


def test_old_list_schema_still_works(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", {"C$": ["public.txt", "secret.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", r"\.txt$",
    ])
    assert "public.txt" in out.out
    assert "secret.txt" in out.out


def test_old_list_schema_with_domain_readable_drops_all(tmp_path, monkeypatch, capsys):
    d = _write_input(tmp_path, "host", {"C$": ["public.txt"]})
    out = _run_main(monkeypatch, capsys, [
        "spider-parser", "-d", f"{d}/", "--domain-readable", r"\.txt$",
    ])
    assert "public.txt" not in out.out      # no ACL data -> not provably readable
    assert "lacks ACL data" in out.err       # one-line stderr note
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_domain_readable.py -k "schema or folder or readable_keeps" -v`
Expected: FAIL — new-schema cases emit folder entries / mis-handle dict values, and the stderr note is absent.

- [ ] **Step 3: Replace the inner loop**

Replace the `for key in a.keys():` block (lines ~242-263) with:

```python
            for key in a.keys():
                if (hostname, key) in exclusions['shares']:
                    continue
                if key == 'IPC$' or (not args.include_sysvol and key == 'SYSVOL'):
                    continue
                share_entry = a[key]
                if isinstance(share_entry, dict):
                    # New schema: path -> metadata dict. File entries have a
                    # "size" key; folder/root records carry only "security".
                    entries = [
                        (path, meta) for path, meta in share_entry.items()
                        if path != '' and isinstance(meta, dict) and 'size' in meta
                    ]
                else:
                    # Old schema: a flat list of file-path strings, no ACL data.
                    if args.domain_readable:
                        acl_warning_needed = True
                        continue
                    entries = [(path, None) for path in share_entry]

                for item, meta in entries:
                    if args.domain_readable and not is_domain_readable(
                        (meta or {}).get('security')
                    ):
                        continue
                    name = re.split(r'[\\/]', item)[-1]
                    if not args.include_dll and name.lower().endswith('.dll'):
                        continue
                    for label, compiled in pattern_items:
                        if compiled.search(name):
                            if label:
                                print(f'{hostname},{key},{label},{item}')
                            else:
                                print(f'{hostname},{key},{item}')
                            matched_shares.add((hostname, key))
                            break
```

- [ ] **Step 4: Add the warning flag init and emit**

Immediately before `for file_path in files:` (line ~223) add:

```python
    acl_warning_needed = False
```

Immediately after the `for file_path in files:` loop ends (before `host_ip_cache = {}`,
line ~264) add:

```python
    if acl_warning_needed:
        print('# Note: --domain-readable set but input lacks ACL data (old schema); those entries were dropped.', file=sys.stderr)
```

(The `# ... lacks ACL data ...` substring satisfies the stderr assertion.)

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest tests/ -v`
Expected: PASS — new tests pass and all pre-existing tests (including
`tests/test_include_dll.py`, `tests/test_emit_blocks.py`) still pass.

- [ ] **Step 6: Commit**

```bash
git add spider_parser.py tests/test_domain_readable.py
git commit -m "Handle dict/list schema and apply --domain-readable filter"
```

---

### Task 5: README + version bump

**Files:**
- Modify: `README.md`
- Modify: `pyproject.toml:7`

- [ ] **Step 1: Document the flag in README**

Find the options/usage section of `README.md` and add a bullet alongside the other
flags (match the surrounding markdown style):

```markdown
- `--domain-readable` — Only output files a normal domain user can read, computed from
  the per-file ACLs in ACL-aware `spider_plus` output (NetExec `feature/spider-plus-acl`).
  Evaluation follows the Windows DACL check (Domain Users / Authenticated Users /
  Everyone / BUILTIN\Users; deny wins only when it precedes the grant). Files whose
  output lacks ACL data (older `spider_plus` schema) cannot be proven readable and are
  dropped.
```

- [ ] **Step 2: Bump the version**

In `pyproject.toml` line 7, change:

```toml
version = "0.3.3"
```

to:

```toml
version = "0.4.0"
```

- [ ] **Step 3: Verify**

Run: `grep -n 'version' pyproject.toml && python -m pytest tests/ -q`
Expected: shows `version = "0.4.0"`; all tests pass.

- [ ] **Step 4: Commit**

```bash
git add README.md pyproject.toml
git commit -m "Document --domain-readable and bump to 0.4.0"
```

---

## Self-Review

**Spec coverage:**
- Flag `--domain-readable`, additive, store_true → Task 3. ✓
- Dict vs list schema handling, file-only via `size`, skip `""` root → Task 4. ✓
- Old-schema drop + stderr note → Task 4 (steps 3-4) + test in Task 4 step 1. ✓
- `is_domain_readable` order-sensitive Windows check, trustees, read rights, error/missing/empty → Task 2. ✓
- `_trustee_is_domain` prefix-strip + case-insensitive → Task 1. ✓
- Tests (unit + e2e + regression) → Tasks 1, 2, 4. ✓
- README + version 0.4.0 → Task 5. ✓

**Placeholder scan:** No TBD/TODO; all code shown in full. ✓

**Type consistency:** `is_domain_readable(security)` takes the inner `security` dict (or
None); callers pass `(meta or {}).get('security')`. `_trustee_is_domain(trustee)` takes a
string. Constants `DOMAIN_TRUSTEES`/`READ_RIGHTS` referenced consistently. `entries` is a
list of `(path, meta-or-None)` tuples in both branches. `acl_warning_needed` defined before
the file loop, set inside, read after. ✓
