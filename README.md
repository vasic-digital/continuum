# Continuum — instant-resume continuation engine

**Revision:** 1
**Last modified:** 2026-07-15T00:00:00Z
**Status:** active
**License:** MIT
**Module:** `github.com/vasic-digital/continuum`

Continuum is a project-agnostic, durable, content-addressed multi-stream **state
snapshot store** that makes resuming a whole parallel-development fleet — every
Track, main stream and agent, all at once — **instant** and **token-cheap**.

It is the mechanical engine behind the "cutting-edge Continuation mechanism"
mandate. It **extends** (never replaces) the existing continuation anchors —
§12.10 (`docs/CONTINUATION.md`), §11.4.127 (session-handoff resumption prompt),
§11.4.131 (standing session-resumption file), §11.4.205 (mechanically-enforced,
machine-derived, atomically-written handoff docs). A fresh session reads **one
snapshot manifest + one compact blob per stream** — not a full re-read of every
handoff document — so resume cost is `O(changed streams)`, not `O(total
history)`.

## Why it is "instant" and cheap

| Property | Mechanism | Anchor |
|---|---|---|
| Whole fleet captured atomically | one Merkle **manifest** references every stream's content-hash | §11.4.205(4) |
| Resume reads O(streams), not O(history) | `RestoreAll` = 1 manifest read + 1 blob/stream; the event ledger is **never** read on the resume path | §11.4.127 |
| Global snapshot costs O(changed) | unchanged streams keep the same content hash → deduped across snapshots | — |
| A wrong resume is impossible | every blob is integrity-checked (bytes must hash to their id) + deterministic round-trip | §11.4.201 |
| No lost update, ever | atomic ref write (temp→fsync→rename→dir-fsync) + append-only ledger | §11.4.205(6) |
| Single writer per stream | a non-owner write is refused | §11.4.206 |
| Crashed-writer never freezes it | advisory lock with **provably-stale** reap (`kill -0`), never steals a live lock | §11.4.180 / §9.2 |
| The verifier cannot bluff | self-validating oracle: golden-good PASS + golden-bad FAIL + negative-control PASS | §11.4.107(10) |

## Install

```bash
go install github.com/vasic-digital/continuum/cmd/continuum@latest
# or, from a checkout:
go build -o continuum ./cmd/continuum
```

Zero external dependencies (Go stdlib only).

## Quick start

```bash
export CONTINUUM_STORE=/path/to/.continuum      # required (never guessed, §11.4.6)

# each stream records its own state (single-writer, §11.4.206)
continuum set --id T1/main --kind main --phase release \
    --next "flash D4" --goal "1.2.1 tag" --owner conductor
continuum set --id T2/feature/mistiq-vader --kind track --next "SPK-512 HAL" --owner worker-2
continuum set --id T4/x --kind track --next "await operator" --owner worker-4 --blocker "operator STOP"
echo '{"stream_id":"agent:ruler","kind":"agent","next_action":"rebind","owner":"ruler"}' | continuum set --json

# atomically snapshot ALL streams into one Merkle manifest
continuum snapshot "fleet at 14:15"

# prove it: integrity + determinism of HEAD, and the self-validating oracle
continuum verify        # -> PASS: HEAD <id>: N stream(s) integrity + determinism OK
continuum selfcheck     # -> good=PASS bad=FAIL negctrl=PASS

# ---- a FRESH session resumes the WHOLE fleet from ONE read ----
continuum resume --short     # one-line SHORT bundle (blocked streams first)
continuum resume --metric    # FULL bundle + measured resume-cost metric
```

`resume --metric` emits the captured resume-cost evidence:

```json
{"snapshot_id":"dfe8…","streams":4,"blobs_read":5,"bytes":504,"est_tokens":126,"wall_micros":152}
```

`blobs_read == 1 + streams` is the load-bearing proof that resume does **not**
read the history.

## Commands

| Verb | Purpose |
|---|---|
| `set` | a stream writes/updates its own state (flags or `--json` on stdin) |
| `snapshot` | atomically capture ALL streams into a new Merkle manifest |
| `resume` | render the compact resume bundle (`--short` / FULL) + `--metric` |
| `restore` | print a stream's (or all streams') committed state as JSON |
| `verify` | deterministic integrity + round-trip check of HEAD (PASS/FAIL/SKIP) |
| `selfcheck` | run the golden-good / golden-bad / negative-control oracle |
| `diff` | O(changed) delta between two snapshots |
| `log` | the append-only event ledger |
| `head` | print the current committed snapshot id |

Store root: `--store <path>` or `$CONTINUUM_STORE` (required; the engine fails
closed and never guesses a project path, §11.4.6 / §11.4.177).

## Architecture

```
cmd/continuum   CLI (thin; all logic in pkg/*)
pkg/model       StreamState / Snapshot / Event + canonical (deterministic) bytes
pkg/hash        sha256 content addressing
pkg/store       content-addressed blob store + atomic refs + append-only ledger
pkg/lock        advisory lock with provably-stale reap (kill -0), never steals a live lock
pkg/snapshot    Engine: Set / Commit (atomic whole-fleet) / RestoreAll / Diff
pkg/resume      the compact SHORT+FULL resume bundle + measured cost Metric
pkg/verify      deterministic verifier + self-validating oracle
pkg/config      decoupling surface: reads only env/args, fails closed, zero project literals
```

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design and
[`docs/RESEARCH.md`](docs/RESEARCH.md) for the deep-research findings that
selected the technology (content-addressed Merkle-DAG + event sourcing +
atomic-durable-write + provably-stale locking).

## Project-agnostic by construction

Continuum carries **zero** project literals (§11.4.28 / §11.4.177). Every
consuming project supplies its own store path, actor identity, and stream naming
as **data** (env vars / args). It is inherited **by reference** as a constitution
submodule under the §11.4.28(C) depth-1 carve-out; see
[`helix-deps.yaml`](helix-deps.yaml).

## Tests

```bash
go test -race ./...          # unit + integration + e2e + stress + chaos, race-clean
go test -cover ./...         # coverage
continuum selfcheck          # the analyzer proves itself (golden good/bad/neg-control)
```

The suite covers: content-addressing idempotency + integrity, atomic ref
round-trip, append-only monotonic ledger across reopen, provably-stale lock reap
vs. live-lock KEEP, single-writer refusal, O(changed) dedup diff, a
byte-identical multi-stream fresh-session round-trip **with a measured resume
metric**, 150-iteration sustained stress (p50/p95/p99 recorded), 12-writer
concurrent contention (zero lost updates, under `-race`), and chaos: on-disk
corruption **detected** then recovered, and a crashed-writer stale lock reaped.

## License

MIT — see [LICENSE](LICENSE).
