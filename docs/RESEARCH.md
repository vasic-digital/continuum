# Continuum — deep research findings

**Revision:** 1
**Last modified:** 2026-07-15T00:00:00Z

Deep-research pass (§11.4.8 / §11.4.99 / §11.4.123) into "instant, cheap resume
of a whole parallel-agent fleet". Every technology below was evaluated against
the constraints: (1) must make resume `O(changed)` not `O(history)`; (2) must be
atomically durable + tamper-evident; (3) must survive a crashed writer without
freezing the fleet; (4) must be language/platform-agnostic and dependency-free
enough to ship as an inherited constitution submodule; (5) must be provable with
anti-bluff captured evidence, not claimed.

## Findings table

| # | Technology | Core idea | Adopted? | What we took / why rejected | Source |
|---|---|---|---|---|---|
| 1 | **Content-addressed store / Merkle-DAG (git object model)** | SHA of canonical bytes = id; identical content shares one id (dedup); a manifest referencing per-object hashes makes a diff `O(changed)` | **YES — core** | The blob store + snapshot manifest are exactly this. Unchanged streams keep their hash → global snapshot costs O(changed); integrity is intrinsic (bytes must hash to id) | git-scm.com/book/en/v2/Git-Internals-Git-Objects |
| 2 | **Event sourcing + snapshot optimization** | append-only event log is the source of truth; a periodic *snapshot* of folded state avoids replaying the whole log to resume | **YES — core** | We keep an append-only ledger (audit + lost-update recovery, §11.4.205(6)) BUT resume reads the latest *snapshot manifest*, never replays the log — the snapshot-optimization that makes resume cheap | microservices.io/patterns/data/event-sourcing.html |
| 3 | **Durable execution (Temporal / Restate / DBOS / Resonate)** | deterministic replay of a workflow's history resumes execution exactly where it stopped | Partially — pattern only | We adopt the *resume-from-committed-state* guarantee, but NOT a workflow runtime: agents are external processes we cannot deterministically replay. We snapshot their *reported state*, not their execution | docs.temporal.io/evaluate/understanding-temporal |
| 4 | **SQLite session extension (changesets/patchsets) + WAL** | record a diff of DB changes; conflict detection on primary key | No (kept design open) | Considered for the store; rejected the dependency — a content-addressed file store is simpler, zero-dep, and already gives dedup + integrity. The changeset *conflict-on-PK* idea informed the single-writer rule (§11.4.206) | sqlite.org/sessionintro.html |
| 5 | **CRDTs (conflict-free replicated data types)** | commutative/associative/idempotent merges give strong eventual consistency without coordination | No | The fleet has a **single writer per stream** (§11.4.206) and a serial merge conductor — we do NOT need multi-writer convergence; a CRDT would add complexity for a property we deliberately forbid | crdt.tech |
| 6 | **CRIU (checkpoint/restore in userspace)** | freeze a live process tree to disk and restore it | No — structurally unfit | Must checkpoint the *whole* tree, needs same-PID restore, no GPU, brittle across kernels. Agents are LLM sessions, not restorable Unix processes. We resume *state*, not a process image (§11.4.112 class) | criu.org/Main_Page |
| 7 | **tmux-resurrect / tmux-continuum** | persist + auto-restore tmux pane layout & (opt-in) contents | Pattern only | Confirms the "periodic snapshot + restore on start" UX. Not a state model — it restores *panes*, not *work state*. The name "continuum" nods to `tmux-continuum`'s auto-save cadence | github.com/tmux-plugins/tmux-resurrect |
| 8 | **dtach / abduco / mosh** | detach a session from its terminal so it survives disconnect | Pattern only | Session-*survival* is orthogonal: those keep a live process alive; we make resume cheap *after* the process is gone (quota kill / new session) | github.com/mobile-shell/mosh |
| 9 | **btrfs / ZFS / XFS / APFS reflink CoW snapshots** | O(1) filesystem snapshot sharing extents | Complementary, not core | The project already uses btrfs reflink for per-track worktrees (§11.4.167). Continuum's *logical* dedup (content hash) is filesystem-agnostic and works on any FS; the two compose (store can live on a reflinked volume) | btrfs.readthedocs.io/en/latest/Subvolumes.html |
| 10 | **LangGraph checkpointers** | persist graph state keyed by `thread_id`; resume a run from the last checkpoint | Pattern confirmation | Validates the "keyed, resumable, content-addressed checkpoint" model for agent graphs. We generalize it below the framework so ANY agent/track/stream (not just a LangGraph node) checkpoints uniformly | langchain-ai.github.io/langgraph/concepts/persistence/ |
| 11 | **Atomic durable write (temp→fsync→rename→dir-fsync)** | `rename(2)` is atomic for readers; dir fsync makes it durable | **YES — core** | Every ref/blob write uses it (§11.4.205(6)); a temp in the *same* dir (never `/tmp`) so the rename is a real move, not a tearable copy | lwn.net/Articles/457667/ (rename/fsync durability) |
| 12 | **Provably-stale lock reap (`kill -0`)** | a lock is reapable only if its holder PID is provably dead | **YES — core** | The 9-hour-freeze fix (§11.4.180): reap a dead-holder lock, KEEP a live one, never steal (§9.2). `kill(pid,0)` is the liveness oracle | man7.org/linux/man-pages/man2/kill.2.html |
| 13 | **Anthropic context compaction (`/compact`, compaction API)** | fold a long transcript into a compact summary to shrink token cost | Adjacent / consumer-side | Compaction shrinks the *transcript*; Continuum shrinks the *resume read* to O(streams). They compose: a fresh session reads the compact resume bundle instead of re-ingesting handoff docs. **UNCONFIRMED:** a specific "132k→2k tokens" figure appeared only in a login-walled secondary source and is NOT relied upon | docs.anthropic.com (Claude Code compaction; figure UNCONFIRMED) |

## Selected architecture

The winning combination is **(1) content-addressed Merkle-DAG + (2) event
sourcing with snapshot-optimization + (11) atomic-durable-write + (12)
provably-stale locking** — a small, zero-dependency, filesystem-agnostic core
that delivers O(changed) snapshots, O(streams) resume, intrinsic tamper-evidence,
crash-safety, and no lost updates, provable with a self-validating oracle
(§11.4.107(10)). Durable-execution (3), SQLite-sessions (4), CRDTs (5),
CRIU (6) were evaluated and rejected with recorded reasons (right column).

## Honest boundaries (§11.4.6)

- Continuum snapshots the **state an agent reports**, not its execution image; it
  cannot deterministically replay an LLM turn (why CRIU/durable-execution runtimes
  were rejected, not merely "not chosen").
- The `est_tokens` field is a documented `bytes/4` heuristic — an approximation of
  resume-read token cost, explicitly not a measured tokenizer count.
- The Anthropic compaction token-ratio figure is **UNCONFIRMED** (login-walled
  secondary source) and is not a load-bearing claim anywhere in this engine.

## Sources verified 2026-07-15

git-internals · microservices.io event-sourcing · docs.temporal.io ·
sqlite.org/sessionintro · crdt.tech · criu.org · tmux-plugins/tmux-resurrect ·
mobile-shell/mosh · btrfs.readthedocs.io · langchain-ai.github.io/langgraph ·
lwn.net rename/fsync · man7 kill(2). (Two items — the Claude-SDK checkpointing
blog and the compaction token-ratio — returned a login-wall 307 and are marked
UNCONFIRMED above per §11.4.6.)
