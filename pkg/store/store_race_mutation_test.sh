#!/usr/bin/env bash
#
# Paired §1.1 mutation for the sequence-race guard (spec 002-anti-slop T007).
#
# Purpose: the FIX does not prove the test works. Only reverting the fix and
# watching the test go RED proves the test can catch the defect. This script
# reverts the lock-held sequence derivation in store.go to the cached-counter
# form the defect lived in, asserts store_race_test.go flips back to FAIL, and
# restores the file byte-for-byte.
#
# Polarity asserted, in both directions:
#   1. BEFORE mutation the guard tests PASS          (else the mutation proves nothing)
#   2. UNDER mutation the guard tests FAIL           (the mutation is caught)
#   3. UNDER mutation the negative control still PASSES
#      -- so the mutation reintroduces THE DEFECT, not general breakage; a
#         mutation that simply broke the package would be indistinguishable
#         from one the guard genuinely caught (§11.4.201(1))
#   4. AFTER restore the guard tests PASS again AND store.go is byte-identical
#      -- a mutation left behind is a §11.4.14 cleanup violation
#
# Restoration runs from a trap on EXIT/INT/TERM, so it happens on every exit
# path including a failed assertion or an interrupt.
#
# Marker note: the injected comment is deliberately self-describing and scoped
# to this script's name. This file necessarily CONTAINS the marker it injects
# (it is the carrier, not residue) -- so restoration is proven by a sha256
# comparison rather than by a marker scan (§11.4.201(7)(a)).
#
# Paths are derived from this script's own location: nothing here is specific
# to any consuming project (§11.4.177).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MODULE_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
TARGET="${SCRIPT_DIR}/store.go"
TEST_FILE="${SCRIPT_DIR}/store_race_test.go"

GUARD_A="TestAppendEventDistinctSeqAcrossHandlesOpenedBeforeAppend"
GUARD_B="TestAppendEventConcurrentHandlesTotalOrder"
CONTROL="TestAppendEventSingleHandleSequenceUnchanged"

EVIDENCE_DIR="${EVIDENCE_DIR:-$(mktemp -d)}"
mkdir -p "${EVIDENCE_DIR}"
BACKUP="${EVIDENCE_DIR}/store.go.orig"

fail() { echo "MUTATION-TEST: FAIL: $*" >&2; exit 1; }
info() { echo "MUTATION-TEST: $*"; }

# --- restoration on EVERY exit path -----------------------------------------
restore() {
  local rc=$?
  if [ -f "${BACKUP}" ]; then
    cp -f "${BACKUP}" "${TARGET}"
    if command -v sha256sum >/dev/null 2>&1; then
      local want got
      want=$(sha256sum "${BACKUP}" | awk '{print $1}')
      got=$(sha256sum "${TARGET}" | awk '{print $1}')
      if [ "${want}" != "${got}" ]; then
        echo "MUTATION-TEST: CRITICAL: restore did not reproduce the original bytes" >&2
        echo "MUTATION-TEST: original preserved at ${BACKUP}" >&2
        exit 1
      fi
    fi
    info "restored ${TARGET} (byte-identical)"
  fi
  exit "${rc}"
}
trap restore EXIT INT TERM

# run_guards <label> -> writes <EVIDENCE_DIR>/<label>.log, echoes go test's own rc
run_guards() {
  local label="$1" rc=0
  # rc is taken from go test itself; a pipeline would hand back the LAST
  # stage's status and silently mask the verdict.
  ( cd "${MODULE_ROOT}" && go test -race -count=1 -run 'TestAppendEvent' -v ./pkg/store/ ) \
    > "${EVIDENCE_DIR}/${label}.log" 2>&1 || rc=$?
  echo "${rc}"
}

verdict_is() { # verdict_is <label> <FAIL|PASS> <TestName>
  grep -qE -- "^ *--- $2: $3 " "${EVIDENCE_DIR}/$1.log"
}

# --- 0. preconditions -------------------------------------------------------
[ -f "${TARGET}" ]    || fail "target not found: ${TARGET}"
[ -f "${TEST_FILE}" ] || fail "guard test not found: ${TEST_FILE}"
command -v go >/dev/null 2>&1 || fail "go toolchain not on PATH"

grep -q 'ev.Seq = last + 1' "${TARGET}" \
  || fail "lock-held derivation 'ev.Seq = last + 1' not found in ${TARGET}; nothing to mutate"
grep -q 'lock.Acquire' "${TARGET}" \
  || fail "append lock not found in ${TARGET}; nothing to mutate"

cp -f "${TARGET}" "${BACKUP}"
ORIG_SHA=$(sha256sum "${TARGET}" | awk '{print $1}')
info "evidence dir: ${EVIDENCE_DIR}"
info "pre-mutation store.go sha256: ${ORIG_SHA}"

# --- 1. BEFORE: the guards must PASS ----------------------------------------
rc_before=$(run_guards pre_mutation)
if [ "${rc_before}" -ne 0 ]; then
  cat "${EVIDENCE_DIR}/pre_mutation.log" >&2
  fail "guards are not GREEN before mutation (rc=${rc_before}); a mutation flip would prove nothing"
fi
info "1/4 pre-mutation guards PASS (rc=0)"

# --- 2. mutate: revert to the cached-counter derivation ---------------------
python3 - "${TARGET}" <<'PY'
import sys
p = sys.argv[1]
src = open(p).read()
old = """	last, err := s.scanLastSeq()
	if err != nil {
		return ev, err
	}
	ev.Seq = last + 1
"""
new = """	// PAIRED-MUTATION (store_race_mutation_test.sh): sequence taken from the
	// per-handle cached counter instead of the ledger tail under the lock.
	if _, err := s.scanLastSeq(); err != nil {
		return ev, err
	}
	ev.Seq = atomic.AddInt64(&s.seq, 1)
"""
if src.count(old) != 1:
    sys.exit("mutation anchor not unique in %s (found %d)" % (p, src.count(old)))
open(p, "w").write(src.replace(old, new))
PY
grep -q 'PAIRED-MUTATION' "${TARGET}" || fail "mutation did not apply"
info "2/4 mutation applied (lock-held derivation -> cached counter)"

# --- 3. UNDER mutation: guards FAIL, control still PASSES -------------------
rc_mutated=$(run_guards mutated)
if [ "${rc_mutated}" -eq 0 ]; then
  cat "${EVIDENCE_DIR}/mutated.log" >&2
  fail "guards still PASS under mutation -- they cannot catch the defect they claim to guard"
fi
verdict_is mutated FAIL "${GUARD_A}" || fail "${GUARD_A} did not FAIL under mutation"
verdict_is mutated FAIL "${GUARD_B}" || fail "${GUARD_B} did not FAIL under mutation"
verdict_is mutated PASS "${CONTROL}" \
  || fail "negative control ${CONTROL} did not PASS under mutation -- the mutation broke the package generally instead of reintroducing the defect"
info "3/4 under mutation: ${GUARD_A} FAIL, ${GUARD_B} FAIL, ${CONTROL} PASS (rc=${rc_mutated})"

# --- 4. restore + prove the guards are GREEN again --------------------------
cp -f "${BACKUP}" "${TARGET}"
NOW_SHA=$(sha256sum "${TARGET}" | awk '{print $1}')
[ "${NOW_SHA}" = "${ORIG_SHA}" ] || fail "restored file sha256 ${NOW_SHA} != original ${ORIG_SHA}"
rc_after=$(run_guards post_restore)
if [ "${rc_after}" -ne 0 ]; then
  cat "${EVIDENCE_DIR}/post_restore.log" >&2
  fail "guards are not GREEN after restore (rc=${rc_after})"
fi
info "4/4 post-restore guards PASS (rc=0), store.go sha256 ${NOW_SHA} == original"

echo "MUTATION-TEST: PASS: guard flips PASS -> FAIL -> PASS; the test catches the defect"
