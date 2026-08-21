# Evidence-chain threat model — measured limits

**Revision:** 1
**Last modified:** 2026-08-21T02:05:00Z

This document records what the chain **does** and — more importantly — what it
**does not** detect. Every row below was produced by running the shipped
verifier against real artifacts, not reasoned about (§11.4.6).

## The measured attack matrix

9-record chain, anchor recorded at 9 entries. `chain verify` is chain-alone;
`anchor verify` is chain-plus-anchor.

| # | attack | chain alone | chain + anchor |
|---|---|---|---|
| 0 | **healthy (control)** | PASS | PASS |
| 1 | mutate a record (`exit_status` 0 → 1) | **DETECTED** | DETECTED |
| 2 | delete a record, no re-chain | **DETECTED** | DETECTED |
| 3 | reorder records, no re-chain | **DETECTED** | DETECTED |
| 4 | **tail truncation** | **PASS** ⚠ | **DETECTED** |
| 5 | **delete + full re-chain** | **PASS** ⚠ | **DETECTED** |

Row 0 is not decoration. Without a healthy control that PASSes, "DETECTED"
everywhere would be indistinguishable from a verifier that simply refuses
everything — which is a false-positive failure rated exactly as seriously as a
missed detection (§11.4.201(1)).

## The two rows the chain alone does not detect

Rows 4 and 5 are the honest limit, and they are **not a defect**. They share one
structural property: **both leave a structurally valid chain**. Truncation drops
the tail and every surviving link still verifies; delete-and-re-chain rebuilds
every `prev_digest` so the result is internally consistent. A chain walk asks
"does each record link to its predecessor?" — and in both cases the answer is
honestly yes.

The property is structural, not incidental:

```
chain_alone detects an attack  ⟺  that attack leaves an INVALID chain
```

That identity is asserted by a test, so the boundary cannot silently drift.

**What closes them is the anchor**, and only the anchor: it records
`head_digest` **and** `entry_count`, so a chain that is *shorter than its
anchor* is caught by the count, and a chain whose anchored prefix hashes
differently is caught by the digest. Both are DETECTED above.

**What must NOT be confused with them:** a *lagging* anchor — a chain
legitimately **longer** than its anchor whose anchored prefix still matches — is
**healthy** and verifies PASS. Truncation and lagging are opposite directions of
the same count comparison, and a head-digest-**equality** check collapses them
into one, reporting every normal append as tampering. That collapse is the named
paired mutation for the anchor verifier; it is observed failing, so the
distinction is enforced rather than assumed.

## Against a same-UID adversary the chain alone is security theatre

State this plainly, because the mechanism looks stronger than it is.

An adversary holding **the same UID as the writer** owns both files. They can
delete a record, re-chain the whole ledger so it is internally consistent, and
then **move the anchor to match** — because the anchor is also just a file that
UID owns. Row 5 is DETECTED in the table above *only because the anchor was not
also rewritten*. An adversary who rewrites both produces a chain and an anchor
that agree, and every check here passes.

Hashing inside a single trust domain detects **accident, truncation, and an
unprivileged actor**. It does not detect an adversary with the writer's own
credentials. No amount of additional hashing changes that; the fix is a
**privilege boundary**, not a stronger digest.

## What would actually strengthen it

Both are **operator-gated options**, recorded in
`specs/002-anti-slop-enforcement/operator-actions.md`. Neither is scheduled
work, and no agent may perform either — both require creating a host boundary.

- **Server-side non-fast-forward protection on the anchor remote.** Puts the
  anchor's history outside the local UID's reach. It is also the only thing that
  lets anchor strength be recorded as `mechanism` rather than `policy`.
- **A privilege-separated signer under a different UID** that refuses to co-sign
  any root which is not an append-only extension of the last one it signed. This
  is the construction that buys real local security, because the signer's record
  of the last root lives outside the writer's UID.

## Honest current strength

Measured on this host, not assumed: there is **no read-only git wire operation
that exposes server-side branch protection**, so the strength probe has no path
returning verified-true and the honest recorded value today is **`policy`**.
Unprobeable is recorded as **unknown with a reason**, never defaulted to either
value — and the validator refuses `policy` *and* `mechanism` against an
unprobeable result, in both directions.

Until an operator takes one of the options above, the system operates at the
weaker strength **and says so**. An unstrengthened system that reports itself
strengthened is precisely the bluff this mechanism exists to prevent.
