# Continuum — design

**Revision:** 1
**Last modified:** 2026-07-15T00:00:00Z

## Goal

Extend the continuation mechanism (§12.10 / §11.4.127 / §11.4.131 / §11.4.205)
into an engine that resumes an entire parallel-development fleet — every Track,
main stream, and agent — **instantly** and at **token cost `O(changed streams)`,
not `O(total handoff history)`**.

## Data model (`pkg/model`)

- **`StreamState`** — one work stream's resumable state: `StreamID`, `Kind`,
  `Phase`, `NextAction`, `Goal`, `Head` (a git-HEAD/checksum anchor), `InFlight`
  jobs, `Evidence`/`Blockers`/`Constraints` lists, `Owner` (single-writer id), and
  a free-form `Fields` map. **No wall-clock timestamp is part of the hashed
  content** — determinism (§11.4.201) requires the content id to be a pure
  function of the semantic state.
- **`Snapshot`** — the Merkle **manifest**: `Streams map[streamID]contentHash`
  plus a `Parent` snapshot id (the DAG edge).
- **`Event`** — one append-only ledger record (`Seq`, `Time`, `Type`, `Stream`,
  `ContentHash`, `SnapshotHash`, `Actor`, `Note`). The ledger is audit + lost-update
  recovery; it is **never** on the resume read path.
- **`Canonical(v)`** — deterministic JSON bytes (`SetEscapeHTML(false)`, stable map
  key order via Go's `encoding/json`, trailing newline trimmed). The content id is
  `sha256(Canonical(v))`, so a re-serialize must byte-match — the verifier's
  round-trip check.

## Store (`pkg/store`)

A content-addressed blob store + atomic refs + append-only ledger, on any
filesystem.

- **Blobs** are write-once, named by their hash (`objects/ab/abcd…`). A second put
  of identical content is a no-op — concurrent writers cannot corrupt each other,
  so only **refs** need a lock.
- **`GetBlob`** re-hashes on read and fails if the bytes don't match the id —
  tamper/corruption is **detected here**, never silently returned (§11.4.201).
- **Refs** (`HEAD`, the working manifest) are written atomically: temp-in-same-dir
  → `fsync` file → `rename(2)` → `fsync` dir (§11.4.205(6)). A reader never sees a
  torn write; the dir fsync makes the rename durable.
- **Ledger** is append-only with a monotonic `Seq` that persists across process
  reopen (loaded by scanning the log's max seq).

## Lock (`pkg/lock`)

An advisory `O_CREATE|O_EXCL` lockfile holding `pid\nstamp`. On contention it
**reaps only a provably-stale** lock:

- holder PID **dead** (`kill(pid,0)` fails) → REAP;
- no PID + **aged past TTL** → REAP;
- holder **alive** → KEEP (never steal — stealing corrupts a concurrent writer,
  §9.2);
- unreadable/ambiguous → conservative KEEP.

Every REAPED/KEEP decision is logged with its evidence (dead PID, age) — the
9-hour-freeze fix (§11.4.180). `ProcessAlive` treats `EPERM` as alive (the PID
exists, owned by another user).

## Engine (`pkg/snapshot`)

- **`Set(st)`** — a stream records its state. Enforces **single-writer** (§11.4.206):
  if the stream already has a non-empty `Owner` and the new `Owner` differs, the
  write is **refused**. Content-addresses the state blob, updates the working
  manifest atomically under the lock, appends a `set` event.
- **`Commit(note)`** — atomically snapshots the **whole** working set into a new
  manifest, links it to the previous HEAD as `Parent`, advances HEAD atomically,
  appends a `snapshot` event. Refuses an empty working set; preconditions every
  referenced blob is present. Because unchanged streams keep their hash, the new
  manifest differs only in changed entries → capturing the fleet is O(manifest).
- **`RestoreAll(id)`** — the instant, byte-identical rehydration of the whole fleet:
  **one manifest read + one blob read per stream**. Never touches the ledger.
- **`Diff(a,b)`** — O(changed) per-stream delta (Added/Removed/Changed) from the two
  manifests.

## Resume (`pkg/resume`)

The compact bundle a fresh session (or the ruler) reads **instead of** re-reading
handoff docs:

- **SHORT** — one line: `Resume N stream(s) from snapshot <id> [k blocked] — top:
  <stream> (<kind>) → <next>`. Blocked streams are surfaced **first** so an
  operator finds the action item in O(1).
- **FULL** — a bounded, structured, **deterministic** block (no volatile lines);
  streams prioritized blocked-first then by id; per-stream Phase/Next/Goal/Head/
  in-flight/blockers/evidence/constraints/fields, all with stable ordering.
- **`Metric`** — captured resume-cost evidence: `Streams`, `BlobsRead` (= `1 +
  streams`, the O(streams) proof), `Bytes`, `EstTokens` (`bytes/4` heuristic),
  `WallMicros`.
- **`GeneratedAtLine`** — the single volatile line, printed **outside** the
  deterministic FULL body (§11.4.201/§11.4.205(5)), so a verifier can re-render
  FULL and byte-compare against committed state.

## Verify (`pkg/verify`)

- **`Verify(HEAD)`** — SKIP if nothing committed; else assert manifest integrity +
  determinism round-trip, then for every stream blob assert integrity + round-trip.
  No timestamp is ever consulted (§11.4.201 — assert the real condition).
- **`SelfCheck`** — the self-validating oracle (§11.4.107(10)): **golden-good** MUST
  PASS, **golden-bad** (a tampered blob) MUST be detected as FAIL, and a
  **negative-control** (HEAD pointed at a legitimately-older valid snapshot) MUST
  PASS. The negative-control is the false-positive guard: it proves the verifier
  distinguishes a *lagging* copy from a *tampered* one (§11.4.201/§11.4.206(3)). A
  verifier that passes its golden-bad, or fails golden-good or the negative-control,
  is itself a bluff and the oracle returns `Overall=FAIL`.

## Config (`pkg/config`)

The decoupling surface (§11.4.28/§11.4.177). The engine carries **zero project
literals**. Store root comes from `--store` or `$CONTINUUM_STORE`; actor from
`$CONTINUUM_ACTOR` (default `host:pid`); lock TTL from `$CONTINUUM_LOCK_TTL_SECONDS`.
When the store root cannot be resolved it **fails closed** with an actionable
message naming `CONTINUUM_STORE` — it never guesses a project path (§11.4.6).

## How it composes with the existing anchors

| Anchor | Continuum's role |
|---|---|
| §12.10 CONTINUATION.md | the machine-derived block of a CONTINUATION doc can be *generated* from a resume render; the doc stays the human narrative, the snapshot is the source of truth |
| §11.4.127 resumption prompt | `resume --short` IS the ready-to-paste first sentence; `resume` (FULL) is the detailed block |
| §11.4.131 standing resumption file | the standing file's machine block = a committed snapshot; always in sync because `set`+`snapshot` are the only way state changes |
| §11.4.205 machine-derived/atomic/enforced | the store IS the machine-derived, atomically-written, tamper-evident substrate §11.4.205 describes |
| §11.4.116 sync channel | the append-only ledger is the event stream; HEAD is the atomically-rewritten snapshot pointer |
| §11.4.147 crashed-agent registry | a per-agent stream's `InFlight` + `Blockers` is the durable "is this work owed?" record that survives a crash |
| §11.4.180 stale-lock reap | the lock package is a reusable implementation of the mandated reaper |
| §11.4.206 single-writer SSoT | enforced by `Set`'s owner check |

## Non-goals (honest boundaries, §11.4.6 / §11.4.112)

- Not a process checkpointer (no CRIU) — resumes *state*, not an execution image.
- Not a multi-writer CRDT — the fleet is single-writer-per-stream by design.
- Not a workflow runtime — it does not replay agent turns; it stores reported state.
- `est_tokens` is a `bytes/4` heuristic, not a tokenizer count.
