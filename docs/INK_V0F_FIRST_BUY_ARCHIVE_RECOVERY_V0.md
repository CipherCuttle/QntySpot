# Ink V0F first-live BUY: archive discovery, not reconstruction

Status: read-only forensic helper. **SAFE STOP; no capital, merge or signing authority.**

## Exact evidence boundary (2026-09-22T22:33:41Z)

The locally executed first-pass diagnostic searched 1,510 filesystem entries and 10
SQLite databases. It found no surviving ledger containing the exact first-live
BUY receipt and the expected original `/tmp/qntyspot-ink-v0f-ink-v0f-1789941991-900.sqlite3`
was missing. The epoch-6 production issuance database passed the reported
integrity/foreign-key checks, contained serials 1–8 and no serial 9; this
read-only diagnostic did **not** verify the receipt signatures. Both configured
Ink RPCs agreed at common block 56,618,010: wallet nonce 1, pending nonce 1,
KRAKMASK balance `4396392944674627615414` atomic, ETH balance
`1999871292488141` wei and router allowance 0. These observations are dated,
not a fresh preflight.

## One bounded archive pass

The earlier tool did not inspect compressed archives. Run the standard-library
helper from the QntySpot repository (no venv, credentials, network or package
installation required):

```bash
python3 ops/ink_v0f_buy_archive_recovery_v0.py
```

By default it searches home, `/mnt`, `/media` and `/tmp`, without following
directory symlinks. Add `--search-root /specific/backup/mount` when necessary.
It examines ZIP, TAR, TGZ, TAR.GZ, TAR.XZ and TAR.BZ2 containers. It reports
unsupported `.zst`, `.7z` and `.rar` files **without opening them**. It is not
recursive inside nested archives or encrypted ZIPs. At most 1,500 archives,
40,000 members per archive, 150 QntySpot-related SQLite files per archive,
512 MiB per archive member and 2 GiB total extracted per archive are inspected.
Sensitive credential or wallet directories and archive member paths are excluded.
Generic SQLite files in unrelated archives are intentionally not opened. A
limit or unsupported format means absence was **not proven**.

Archive contents are never extracted by their embedded paths. Safe regular
SQLite members (plus any `-wal`/`-shm` siblings) are copied into a new
mode-0700 private forensic case. Only original-BUY-matching or plausible
partial QntySpot candidates are retained, with files mode-0600. ZIP/TAR
sources are not modified. The generated JSON report omits canonical policy,
raw signed bytes and wallet secrets; review archive paths before sharing it.

An exact candidate needs one joined original receipt, FILLED BUY, 0.001 ETH
input, `4396392944674627615414` KRAKMASK output, a valid source cycle,
SQLite integrity OK and zero foreign-key violations. **This is candidate
identification, not permission to reuse the snapshot**: separately prove
unique inventory carry, all historical serial-8 residue and absence of signed
or unresolved external actions, full ledger replay equivalence, and fresh
independent chain truth before treating any recovered file as operational.

If the pass finds no candidate, leave the existing wallet untouched and
explicitly document the missing authoritative historical state. A new DB built
only from chain transfers would omit the exact original policy and serial-8
history; do not silently replace the original ledger, issue serial 9 or run a
SELL against fabricated provenance. The separate frozen-runtime prepare script
must also not touch the only historical evidence copy: run destructive/normal
SQLite preflight against a verified private working copy, not the quarantine.
