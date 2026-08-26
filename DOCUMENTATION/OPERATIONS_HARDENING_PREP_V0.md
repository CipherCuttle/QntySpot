# Operations hardening preparation V0

This is an authority-neutral preparation substrate for a future single-host
daemon. It provides a Linux advisory process lock, read-only SQLite
verification, native SQLite online backup, temporary restore verification, and
a deterministic read-only status report.

The substrate does not sign, access credentials, select assets, call a venue,
open a public socket, reconcile outcomes, release reservations, or activate a
daemon. `SAFE_HALT` and `QUARANTINED` reservations remain visible and counted.

The systemd file in this directory is documentation only. Its `ExecStart` is
`DEFERRED`; it must not be installed, enabled, or started from this phase.

`PrivateNetwork=yes` is appropriate for this authority-neutral template. A
future networked executor must receive its own reviewed service contract and
must not inherit this setting blindly.
