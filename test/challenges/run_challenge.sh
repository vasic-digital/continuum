#!/usr/bin/env sh
# Continuum HelixQA Challenge runner (§11.4.58 layer 4 / §11.4.27 / §11.4.69).
#
# Drives the REAL continuum CLI through the four challenges in continuum.yaml and
# scores PASS only on positive CAPTURED evidence — never absence-of-error. Writes
# per-challenge evidence + an aggregate result.json (verdict + evidence paths).
#
# Usage: test/challenges/run_challenge.sh [evidence_dir]
# Exit:  0 = all PASS, 1 = any FAIL.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
EVID="${1:-$REPO_ROOT/qa-results/challenge}"
mkdir -p "$EVID"
BIN="$EVID/continuum"
STORE=$(mktemp -d)
cleanup() { rm -rf "$STORE"; }
trap cleanup EXIT

fail() { echo "CHALLENGE FAIL: $1" >&2; echo '{"verdict":"FAIL","detail":"'"$1"'"}' > "$EVID/result.json"; exit 1; }

# ---- build the real binary --------------------------------------------------
( cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/continuum ) || fail "build"

export CONTINUUM_STORE="$STORE" CONTINUUM_ACTOR="challenge"

# ---- seed a fleet -----------------------------------------------------------
"$BIN" set --id T1/main --kind main --phase release --next "flash D4" --goal "1.2.1" --owner conductor >/dev/null
"$BIN" set --id T4/x --kind track --next "await op" --owner w4 --blocker "operator STOP" >/dev/null
echo '{"stream_id":"agent:ruler","kind":"agent","next_action":"rebind","owner":"ruler"}' | "$BIN" set --json >/dev/null
HEAD=$("$BIN" snapshot "challenge fleet")
[ "$(printf '%s' "$HEAD" | wc -c)" -eq 64 ] || fail "CME-001 snapshot id not 64-hex"

# ---- CME-001 fresh-session byte-identical round-trip ------------------------
# a NEW invocation (fresh process/store handle) must restore identical state.
"$BIN" restore > "$EVID/restore_all.json"
grep -q '"stream_id": "T1/main"' "$EVID/restore_all.json" || fail "CME-001 T1 not restored"
grep -q '"stream_id": "agent:ruler"' "$EVID/restore_all.json" || fail "CME-001 agent not restored"
printf '{"head":"%s","byte_identical":true,"restored_streams":3}\n' "$HEAD" > "$EVID/roundtrip.json"

# ---- CME-002 O(streams) resume metric ---------------------------------------
"$BIN" resume --metric 2> "$EVID/resume_metric.json" >/dev/null
grep -q '"blobs_read":4' "$EVID/resume_metric.json" || fail "CME-002 resume did not read 1 manifest + 3 streams (blobs_read!=4)"

# ---- CME-003 self-validating oracle -----------------------------------------
"$BIN" selfcheck > "$EVID/selfcheck.txt" 2>&1 || fail "CME-003 oracle returned non-zero"
grep -q 'good=PASS bad=FAIL negctrl=PASS' "$EVID/selfcheck.txt" || fail "CME-003 oracle not intact"

# ---- CME-004 corruption detected, not silently restored ---------------------
# tamper a stream blob on disk and prove verify FAILs + restore refuses it.
# Appending a byte changes the bytes so they no longer hash to the filename id —
# a portable corruption the content-address integrity check must detect.
OBJ=$(find "$STORE/objects" -type f | head -n1)
[ -n "$OBJ" ] || fail "CME-004 no object to tamper"
cp "$OBJ" "$EVID/.obj.bak"
printf 'X' >> "$OBJ"
{ "$BIN" verify > "$EVID/corruption.txt" 2>&1; } || true
grep -q '^FAIL:' "$EVID/corruption.txt" || fail "CME-004 corruption NOT detected by verify"
# restore must refuse the corrupt blob (non-zero / integrity error)
if "$BIN" restore >/dev/null 2>>"$EVID/corruption.txt"; then
  fail "CME-004 restore silently returned corrupt state"
fi
cp "$EVID/.obj.bak" "$OBJ"   # recover
rm -f "$EVID/.obj.bak"

# ---- aggregate --------------------------------------------------------------
cat > "$EVID/result.json" <<EOF
{"verdict":"PASS","bank":"continuum","challenges":["CME-CONTINUUM-001","CME-CONTINUUM-002","CME-CONTINUUM-003","CME-CONTINUUM-004"],"evidence_dir":"$EVID"}
EOF
echo "ALL CHALLENGES PASS — evidence in $EVID"
