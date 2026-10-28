# Continuum FAQ

**Why do I see a `.q` directory next to my lockfile?** It is the ticket queue
used for cross-process fairness. It is empty when nobody is waiting.

**Is it safe to delete `<lock>.q`?** Yes while idle. Waiters re-create it. If it
cannot exist the lock still works, only without fairness.

**A process was killed while waiting. Does it block others?** No. Its ticket is
removed by the next scan because its pid is dead; TTL is the backstop for pid
reuse.

**Why is a single `Set` slow on my disk?** Each durable write fsyncs. About 48 ms
per `Set` was measured on ext4; tmpfs is about 0.5 ms. Continuum does not skip
these fsyncs.

**Does the incremental scan weaken tamper detection?** The append path trusts what
this handle already verified. Use `continuum verify` (or open a fresh handle) to
re-check the whole ledger and chain.

**Why was `Release` leaving a lockfile after `chdir`?** Fixed in 0.1.2: the lock
path is stored absolute.

**A process was stopped with Ctrl-Z while waiting; do others wait for it?** Not for
long. A waiting process refreshes its ticket; a ticket without a recent heartbeat
(default max(2 s, 20 x Poll)) is reaped even though the pid is alive, and the
frozen process re-enqueues when it resumes.
