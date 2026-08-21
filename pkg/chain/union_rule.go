// Union rule — WHICH calls require a chain entry, and, just as bindingly,
// which do NOT (FR-026, FR-027, FR-028).
//
// The rule is a union of two clauses and one deliberate exclusion:
//
//	FR-026  a STATE-CHANGING call (write, exec, deploy) REQUIRES an entry.
//	        It changed the world; if it is not recorded, the record of what
//	        happened is incomplete no matter who cited what.
//	FR-028  a read CITED AS EVIDENCE REQUIRES an entry. A claim resting on a
//	        read that was never recorded rests on nothing.
//	FR-027  a read that is NOT cited requires NONE, and the chain verifies
//	        COMPLETE without it.
//
// FR-027 is not a convenience, it is a correctness requirement doing two jobs.
//
// It bounds volume: the measured working rate is 2,000-5,000 entries/day with
// 10^4 bursts. Recording every read instead of every CITED read inflates that
// by orders of magnitude, and a chain nobody can afford to verify is a chain
// nobody verifies.
//
// And it stops the gate refusing correct behaviour. A gate that demands an
// entry for every read is not stricter — it is WRONG, and per §11.4.201(1) a
// false refusal is a FAIL-bluff exactly as serious as a false pass, because it
// condemns healthy work and teaches people to route around the verifier. That
// is why TestUnionRule_UncitedReadRequiresNoEntry is a hard assertion rather
// than a comment, and why "require an entry for every read" is the paired
// mutation for this file: it must make the FR-027 half FAIL while the FR-026
// and FR-028 halves keep passing.
package chain

import "fmt"

// Call kinds (closed set).
const (
	// CallWrite, CallExec and CallDeploy are STATE-CHANGING: they alter the
	// world outside the process.
	CallWrite  = "write"
	CallExec   = "exec"
	CallDeploy = "deploy"
	// CallRead observes without altering. It requires an entry only when it is
	// cited as evidence.
	CallRead = "read"
)

// Call is one recorded interaction, classified for the union rule.
//
// Cited means "this call's result is offered as evidence for a claim". It is
// irrelevant to a state-changing call — a write changed the world whether or
// not anyone cited it — and decisive for a read.
type Call struct {
	Kind  string `json:"kind"`
	Cited bool   `json:"cited"`
}

// IsStateChanging reports whether k alters state outside the process.
func IsStateChanging(k string) bool {
	switch k {
	case CallWrite, CallExec, CallDeploy:
		return true
	default:
		return false
	}
}

// RequiresEntry applies the union rule to one call.
//
// The default branch fails CLOSED (§11.4.252): an unrecognised kind has not
// been classified, and the safe direction for an unclassified call is to demand
// the evidence rather than to let a possibly state-changing call escape the
// record unnoticed. This is NOT in tension with FR-027 — that clause is about
// the KNOWN class "uncited read", which is classified and excluded by name
// below. Refusing to guess about an unknown kind is not the same as demanding
// an entry for a read we understand perfectly well.
func RequiresEntry(c Call) bool {
	switch c.Kind {
	case CallWrite, CallExec, CallDeploy:
		return true
	case CallRead:
		// FR-027, the load-bearing exclusion. Changing this to `return true`
		// is the paired mutation, and it MUST break
		// TestUnionRule_UncitedReadRequiresNoEntry.
		return c.Cited
	default:
		return true
	}
}

// KindEntryMissing is reported when the chain holds fewer entries than the
// union rule requires for the calls presented.
const KindEntryMissing = "chain_entry_ABSENT"

// RequiredEntries counts the calls that the union rule says must be recorded.
func RequiredEntries(calls []Call) int {
	n := 0
	for _, c := range calls {
		if RequiresEntry(c) {
			n++
		}
	}
	return n
}

// VerifyComplete verifies the chain structurally AND checks it against the
// union rule's demand for the calls presented.
//
// A chain that is missing entries only for UNCITED READS is COMPLETE, and this
// function must say so — that is FR-027 stated where it actually bites.
//
// # Honest boundary (§11.4.6) — read before trusting this
//
// Call carries no identity: no call id, no digest, no correlation key. So this
// function CANNOT match a specific call to a specific record, and it does not
// pretend to. What it checks is that the chain holds at least as many entries
// as the rule requires. That is the strongest SOUND check available at this
// layer, and it is genuinely useful — it catches a producer that recorded
// nothing, or recorded fewer entries than it made required calls.
//
// What it therefore does NOT catch: a chain with the right NUMBER of entries
// describing the wrong calls. Closing that needs a correlation key on Call and
// a per-call join, which is a change to the recording path (T336a's execution
// field set), not something this function can conjure from the data it is
// given. Reporting per-call correlation from a count would be the precise
// overstatement this feature exists to prevent.
//
// Structural failure dominates: if the chain itself is broken or unwalkable,
// that verdict is returned unchanged rather than being masked by a count that
// happens to add up.
func VerifyComplete(recs []Record, calls []Call) Report {
	rep := Verify(recs)
	if rep.Verdict != PASS {
		return rep
	}

	required := RequiredEntries(calls)
	if len(recs) < required {
		return Report{
			Verdict: DETECTED,
			Findings: []Finding{{
				Kind: KindEntryMissing,
				Seq:  0, // no single record is at fault; the shortfall is of the set
				Detail: fmt.Sprintf(
					"union rule requires %d entries for %d calls (state-changing calls and cited reads); the chain holds %d",
					required, len(calls), len(recs)),
			}},
		}
	}
	return Report{Verdict: PASS}
}
