# Continuum manual: locking and ledger behaviour (0.1.2)

**Revision:** 1

## Lock acquisition order

`lock.Acquire(path, Options{Wait, Poll, TTL})` returns when the caller holds the
lock or `Wait` elapses. Order of service:

1. Within one process, goroutines pass a FIFO gate keyed by the canonical path.
2. Across processes, contenders take a ticket in `<path>.q/` and only the head of
   the queue tries to create the lockfile. With no contention no ticket is made.
3. Mutual exclusion is the exclusive create of the lockfile; the queue only
   decides who tries next.

## What gets reaped

| Object | Reaped when |
|---|---|
| Lockfile | holder pid is dead, or aged past TTL with no live holder; an empty or unparseable lockfile (crash residue: the lockfile is not fsynced) older than TTL |
| Queue ticket | owner pid is dead, or ticket older than TTL, or no heartbeat for the staleness bound (default max(2 s, 20 x Poll)): a waiter that is alive but frozen (SIGSTOP, Ctrl-Z) stops heartbeating and no longer blocks a free lock |

A waiting process refreshes its ticket's mtime about four times per staleness
bound. A live holder is not evicted under normal operation (exceptions: a holder suspended for longer than the TTL between create and stamp, a forward-skewed filesystem clock, and the documented reaper read-then-Remove window). Every decision is written to the evidence log
with the pid and reason.

## Degraded mode

If `<path>.q/` cannot be created or read, `Acquire` falls back to the plain
create-and-poll protocol: still safe, no longer fair.

## Ledger append

`AppendEvent` holds the append lock, reads only the part of the ledger it has not
verified yet, assigns `last+1`, writes one line and fsyncs. The verified prefix
is cached with a 256-byte window of its last bytes; if the file was replaced,
truncated, or rewritten so that window differs, the whole ledger is verified
again. A rewrite that reproduces the window byte for byte, or touches only
earlier bytes, is caught by `verify`, not by the append path. A malformed or
sequence-less line in the unverified part refuses the append
(`ErrUnverifiableTail`).

## Tuning

`CONTINUUM_LOCK_TTL_SECONDS` sets the TTL of the snapshot lock; the ledger append
lock uses the library default (2 minutes). Poll defaults to 25 ms for callers; the
head of a queue polls every 2 ms when Poll is larger than that.
