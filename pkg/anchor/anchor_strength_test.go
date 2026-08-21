// T312 — RED: anchor strength is PROBED and RECORDED, never assumed (FR-038).
//
// The distinction this file exists to hold: POLICY-FORBIDDEN IS NOT
// MECHANICALLY-PREVENTED. "We have a rule against force-pushing" and "the
// server rejects a non-fast-forward push" are different facts with different
// security value, and only the second is `mechanism`. Recording `mechanism`
// because the rule exists — rather than because the probe came back positive —
// is precisely the theatre this feature exists to prevent.
//
// Today's honest value on this host is `policy`.
//
// Three outcomes, and the third is the one usually missed:
//
//	probe says protected      -> mechanism
//	probe says NOT protected  -> policy
//	probe could not run       -> SKIP with a reason, and NEITHER value
//
// An unprobeable remote yielding `policy` would be a quiet downgrade of an
// UNKNOWN into a claim (§11.4.6). Unknown is reported as unknown.
//
// Contract added by this file:
//
//	type ProtectionProbe func() (protected bool, err error)
//	type StrengthResult { Verdict Verdict; Strength string; Reason string }
//	func ProbeStrength(ProtectionProbe) StrengthResult
//	func ValidateRecordedStrength(recorded string, probed StrengthResult) error
//
// Paired mutation (T321): default the field to `mechanism` -> this test MUST fail.
package anchor_test

import (
	"errors"
	"testing"

	"github.com/vasic-digital/continuum/pkg/anchor"
)

func TestStrengthIsDrawnFromTheClosedSet(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protected bool
		want      string
	}{
		{"protection verified enabled", true, anchor.StrengthMechanism},
		{"protection verified absent", false, anchor.StrengthPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := anchor.ProbeStrength(func() (bool, error) { return tc.protected, nil })
			if res.Verdict != anchor.PASS {
				t.Fatalf("probe returned a definite answer but verdict is %s (%s)", res.Verdict, res.Reason)
			}
			if res.Strength != tc.want {
				t.Fatalf("strength=%q, want %q", res.Strength, tc.want)
			}
		})
	}
}

// TestNoEvidenceOfMechanicalPreventionReadsPolicy states the default direction
// explicitly: absent positive evidence, the weaker claim.
func TestNoEvidenceOfMechanicalPreventionReadsPolicy(t *testing.T) {
	res := anchor.ProbeStrength(func() (bool, error) { return false, nil })
	if res.Strength == anchor.StrengthMechanism {
		t.Fatal("no evidence of mechanically-prevented rewriting, yet strength read `mechanism`. " +
			"Policy-forbidden is not mechanically-prevented.")
	}
	if res.Strength != anchor.StrengthPolicy {
		t.Fatalf("strength=%q, want %q", res.Strength, anchor.StrengthPolicy)
	}
}

// TestUnprobeableRemoteSkipsWithReasonAndClaimsNeitherValue is the honest-
// unknown leg. A remote that cannot be reached tells us nothing, and nothing is
// what must be recorded.
func TestUnprobeableRemoteSkipsWithReasonAndClaimsNeitherValue(t *testing.T) {
	res := anchor.ProbeStrength(func() (bool, error) {
		return false, errors.New("dial tcp: connect: network is unreachable")
	})
	if res.Verdict != anchor.SKIP {
		t.Fatalf("an unprobeable remote returned %s, want SKIP", res.Verdict)
	}
	if res.Strength == anchor.StrengthPolicy || res.Strength == anchor.StrengthMechanism {
		t.Fatalf("an unprobeable remote recorded strength=%q. Neither value may be claimed "+
			"from a probe that did not run — that converts an UNKNOWN into a fact (§11.4.6).",
			res.Strength)
	}
	if res.Reason == "" {
		t.Error("SKIP carried no reason; an honest skip names why it could not decide")
	}
}

// TestRecordedMechanismWithoutProbeEvidenceIsRefused is the enforcement half:
// it is not enough that the probe is honest, the RECORD must match it.
func TestRecordedMechanismWithoutProbeEvidenceIsRefused(t *testing.T) {
	noEvidence := anchor.ProbeStrength(func() (bool, error) { return false, nil })
	if err := anchor.ValidateRecordedStrength(anchor.StrengthMechanism, noEvidence); err == nil {
		t.Fatal("an anchor recording `mechanism` was ACCEPTED against a probe that found no " +
			"protection. This is the exact overstatement FR-038 forbids.")
	}

	unprobeable := anchor.ProbeStrength(func() (bool, error) { return false, errors.New("unreachable") })
	if err := anchor.ValidateRecordedStrength(anchor.StrengthMechanism, unprobeable); err == nil {
		t.Fatal("an anchor recording `mechanism` was ACCEPTED against a probe that could not run")
	}
	if err := anchor.ValidateRecordedStrength(anchor.StrengthPolicy, unprobeable); err == nil {
		t.Fatal("an anchor recording `policy` was ACCEPTED against a probe that could not run; " +
			"an unknown must not be recorded as either value")
	}
}

// TestRecordedStrengthMatchingTheProbeIsAccepted is the false-positive guard:
// the validator must not simply refuse every `mechanism`.
func TestRecordedStrengthMatchingTheProbeIsAccepted(t *testing.T) {
	verified := anchor.ProbeStrength(func() (bool, error) { return true, nil })
	if err := anchor.ValidateRecordedStrength(anchor.StrengthMechanism, verified); err != nil {
		t.Fatalf("`mechanism` recorded against a probe that VERIFIED protection was rejected: %v.\n"+
			"The rule is 'record what was probed', not 'never say mechanism' — a validator that "+
			"refuses a true claim is as wrong as one that accepts a false one.", err)
	}
	absent := anchor.ProbeStrength(func() (bool, error) { return false, nil })
	if err := anchor.ValidateRecordedStrength(anchor.StrengthPolicy, absent); err != nil {
		t.Fatalf("`policy` recorded against a probe that found no protection was rejected: %v", err)
	}
}
