# Changelog

## continuum-0.1.2 (2026-10-28)

### Fixed
- Cross-process lock starvation (R1): contenders now queue by ticket
  (`<lock>.q/`), so a process that releases and re-acquires in a tight loop can
  no longer starve a waiter in another process. Measured before the fix: waiter
  served after 251, 265, 325, 457 and 640 holder turns (5 of 5 runs, limit 60);
  after: 3-4 turns.
- A queued waiter heartbeats its ticket; a ticket with no heartbeat is reaped even
  though its owner pid is alive, so a frozen waiter cannot block a free lock for
  the whole TTL. The timeout error now says the queue may be blocked, not only held.
- An empty or unparseable lockfile older than TTL (what an OS crash leaves, since
  the lockfile is not fsynced) is reaped instead of being kept forever.
- C9: `Lock.path` is absolute, so `Release` after a `chdir` removes the real
  lockfile instead of orphaning it.
- C10: in-process gates are keyed by the canonical path (directory symlinks
  resolved), so two spellings of one lock share a gate.

### Performance
- R2: `AppendEvent` verifies the ledger incrementally (resumes at the verified
  prefix, guarded by a 256-byte window so truncate-and-regrow of the same inode
  voids the cache; an unterminated tail is never cached; line reads are bounded) instead of re-parsing the whole file under the lock on every append.
- The lockfile is no longer fsynced (it carries no durable data; stale stamps are
  reaped by dead-pid check or, if empty, by age). Measured on ext4 under the same
  benchmark: 7-9 ms per acquire/release cycle before, 0.1-0.6 ms after.
- Event and blob writes still fsync by design (durability).

### Tests
- C11: the timer/free-gate race is now testable through an injectable timer.
- New: cross-process starvation test, ticket-queue unit tests, SIGKILL chaos test
  (queued waiters and the holder killed), incremental-scan cost and correctness
  tests (other handle, truncation, replaced file, garbage, seq-less line,
  unterminated tail).

### Known limits
- Reaping a stale lockfile or ticket is read-then-remove; two reapers racing on
  the same object can both remove it (pre-existing, bounded by the O_EXCL create
  that follows).
- The head waiter logs KEEP decisions at its poll rate when evidence is enabled.
- Ticket order is FIFO only to clock resolution (nanosecond stamps, cross-process).
- A handle does not re-read bytes it already verified; old-line tampering is
  caught by `verify`, not by the append path.
- Per-write fsync remains the throughput floor on journalled disks; group commit
  is not implemented.

## continuum-0.1.1
In-process FIFO gate for lock fairness.

## continuum-0.1.0
Initial release.
