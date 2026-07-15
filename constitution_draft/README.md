# Constitution integration DRAFT — Continuum instant-resume engine

**This is a DRAFT for operator/conductor review. It is intentionally NOT
self-committed to the constitution submodule.** Applying a constitution change
must follow §11.4.26 (fetch+pull first → apply → validate → commit+push to all
upstreams → post-merge validation → bump consuming-project pointer) and the
§11.4.35 canonical-root rules.

## What this integrates

Continuum (`github.com/vasic-digital/continuum`, mirror
`gitlab.com/vasic-digital/continuum`) — the mechanical engine that makes
instant, token-cheap resume of a whole parallel-development fleet possible. It
**extends** the existing continuation family (§12.10 / §11.4.127 / §11.4.131 /
§11.4.205); it does not replace any of them.

## Three parts to apply

### 1. Add as a depth-1 reusable-engine submodule (§11.4.28(C) carve-out)

The §11.4.28(C) carve-out permits the constitution submodule ITSELF to host
depth-1 reusable engines under `constitution/submodules/<name>/`, provided each
ships a `helix-deps.yaml` and nests zero further own-org submodules. Continuum
qualifies (leaf engine, zero own-org deps — see its `helix-deps.yaml`).

```bash
# run INSIDE the constitution submodule working tree, after §11.4.26 step 1 fetch+pull
git submodule add git@github.com:vasic-digital/continuum.git submodules/continuum
git -C submodules/continuum remote set-url --add --push origin git@github.com:vasic-digital/continuum.git
git -C submodules/continuum remote set-url --add --push origin git@gitlab.com:vasic-digital/continuum.git
```

`.gitmodules` gains (see `integration.gitmodules.patch`):

```
[submodule "submodules/continuum"]
	path = submodules/continuum
	url = git@github.com:vasic-digital/continuum.git
```

### 2. Insert the new anchor §11.4.207

Insert the anchor in `ANCHOR_11_4_207.md` into `constitution/Constitution.md`
(full text) in numerical order after §11.4.206, and mirror the compact form into
`constitution/CLAUDE.md`, `constitution/AGENTS.md`, `constitution/QWEN.md`,
`constitution/GEMINI.md` in lockstep (§11.4.157). Add its propagation gate
`CM-COVENANT-114-207-PROPAGATION` (literal `11.4.207`) + recommended mechanism
gate `CM-CONTINUUM-RESUME-ENGINE-PRESENT` + a paired §1.1 mutation, per the
existing gate-authoring pattern (gate-code is a separate work item).

### 3. Record it in the submodule catalogue

Add the `helix-deps.yaml` entry (see `catalogue_entry.yaml`) to whatever
submodule catalogue the constitution maintains (§11.4.74 catalogue-first
discovery), so consumers find "instant resume" before reimplementing it.

## Validation before commit (§11.4.26 step 3 + §11.4.32)

- `cd submodules/continuum && go test -race ./...` → all green
- `continuum selfcheck` → `good=PASS bad=FAIL negctrl=PASS`
- run the propagation gate + its paired mutation → gate FAILs on the mutation
- verify the anchor literal `11.4.207` appears across all five canonical files
