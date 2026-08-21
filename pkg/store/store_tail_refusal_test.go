// T313 — RED: AppendEvent must REFUSE to assign a sequence onto a ledger tail
// it could not verify.
//
// ############################################################################
// # THIS FILE IS AN INTENTIONAL RED. It is EXPECTED to fail until T316 lands. #
// #                                                                          #
// # It is NOT a regression of the lock-held sequence-derivation fix that this #
// # package already carries. That fix (owned by T006) closed the DUPLICATE-   #
// # SEQUENCE race and is deliberately NOT re-asserted here: re-running a RED  #
// # that another task already turned GREEN could be recorded only by          #
// # fabrication or by re-breaking fixed code, and §11.4.227 refuses           #
// # restatement-as-progress. That property's evidence lives with T005/T007.   #
// #                                                                          #
// # What is missing today is a DIFFERENT property, on the same code path:     #
// # scanLastSeq() silently skips any line it cannot parse                     #
// #     if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Seq > last
// # so a torn or garbage tail is treated as absent rather than as a fault,    #
// # and AppendEvent hands out a sequence derived from a tail it never         #
// # verified. The chain built on this ledger would then have no trustworthy   #
// # total order — and it would say nothing about that.                        #
// #                                                                          #
// # T316 implements the refusal under the SAME exclusive lock AppendEvent     #
// # already holds. Its paired mutation is: map the unverifiable-tail branch   #
// # to "assign a sequence anyway" -> these tests MUST fail again.             #
// ############################################################################
package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
)

// seedLedger opens a store and appends n healthy events, returning the root.
func seedLedger(t *testing.T, n int) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := s.AppendEvent(model.Event{
			Time: "2026-08-21T12:00:00Z", Type: "set", Stream: "T1/main",
		}); err != nil {
			t.Fatalf("seeding append %d: %v", i, err)
		}
	}
	return s, root
}

func ledgerPath(root string) string { return filepath.Join(root, logDir, logFile) }

// mentionsUnverifiableTail reports whether an error names the reason rather
// than failing anonymously. FR-030: a refusal must say WHY, or an operator
// cannot tell "the store is corrupt" from "the disk is full".
func mentionsUnverifiableTail(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	for _, want := range []string{"tail", "verif", "malformed", "corrupt", "unparse"} {
		if strings.Contains(m, want) {
			return true
		}
	}
	return false
}

// TestAppendEvent_RefusesTornTail_RED covers the realistic crash artifact: a
// partial line left behind when a process died between write() and fsync().
func TestAppendEvent_RefusesTornTail_RED(t *testing.T) {
	s, root := seedLedger(t, 3)

	b, err := os.ReadFile(ledgerPath(root))
	if err != nil {
		t.Fatalf("reading ledger: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 seeded lines, got %d", len(lines))
	}
	// Tear the last record in half — valid JSON prefix, no closing brace.
	torn := lines[len(lines)-1]
	torn = torn[:len(torn)/2]
	lines[len(lines)-1] = torn
	if err := os.WriteFile(ledgerPath(root), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("writing torn ledger: %v", err)
	}

	ev, err := s.AppendEvent(model.Event{Time: "2026-08-21T12:10:00Z", Type: "set"})
	if err == nil {
		t.Fatalf("AppendEvent ACCEPTED a torn tail and assigned seq %d — a sequence derived "+
			"from a tail that was never verified. It must refuse instead. (T316)", ev.Seq)
	}
	if !mentionsUnverifiableTail(err) {
		t.Errorf("AppendEvent refused but did not name the reason: %v", err)
	}
}

// TestAppendEvent_RefusesGarbageTail_RED covers a non-JSON tail (a stray write
// into the ledger by something that is not this package).
func TestAppendEvent_RefusesGarbageTail_RED(t *testing.T) {
	s, root := seedLedger(t, 2)

	f, err := os.OpenFile(ledgerPath(root), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("opening ledger: %v", err)
	}
	if _, err := f.WriteString("this is not a record\n"); err != nil {
		t.Fatalf("appending garbage: %v", err)
	}
	f.Close()

	ev, err := s.AppendEvent(model.Event{Time: "2026-08-21T12:11:00Z", Type: "set"})
	if err == nil {
		t.Fatalf("AppendEvent ACCEPTED a garbage tail and assigned seq %d; the unparseable "+
			"line was silently skipped rather than reported. (T316)", ev.Seq)
	}
	if !mentionsUnverifiableTail(err) {
		t.Errorf("AppendEvent refused but did not name the reason: %v", err)
	}
}

// TestAppendEvent_AcceptsHealthyTail_NegativeControl is the §11.4.201(1)
// false-positive guard, and it PASSES TODAY. It must keep passing after T316:
// a refusal branch that refuses everything is not a fix, it is an outage, and a
// false refusal is a FAIL-bluff exactly as serious as a false pass.
//
// It is deliberately in the same file as the two REDs so the pair cannot drift
// apart — anyone who makes the REDs pass by refusing unconditionally breaks
// this one in the same run.
func TestAppendEvent_AcceptsHealthyTail_NegativeControl(t *testing.T) {
	s, root := seedLedger(t, 3)

	ev, err := s.AppendEvent(model.Event{Time: "2026-08-21T12:12:00Z", Type: "set"})
	if err != nil {
		t.Fatalf("AppendEvent REFUSED a healthy ledger: %v", err)
	}
	if ev.Seq != 4 {
		t.Errorf("healthy append got seq %d, want 4", ev.Seq)
	}
	// An empty ledger is also healthy: "nothing yet" is not "unverifiable".
	root2 := t.TempDir()
	s2, err := Open(root2)
	if err != nil {
		t.Fatalf("Open(empty): %v", err)
	}
	ev2, err := s2.AppendEvent(model.Event{Time: "2026-08-21T12:13:00Z", Type: "set"})
	if err != nil {
		t.Fatalf("AppendEvent REFUSED an empty (never-written) ledger: %v", err)
	}
	if ev2.Seq != 1 {
		t.Errorf("first append on an empty ledger got seq %d, want 1", ev2.Seq)
	}
	_ = root
}
