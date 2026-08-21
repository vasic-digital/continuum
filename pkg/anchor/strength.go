package anchor

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Anchor strength is PROBED and RECORDED, never assumed (FR-038).
//
// The distinction this file exists to hold:
//
//	POLICY-FORBIDDEN IS NOT MECHANICALLY-PREVENTED.
//
// "We have a rule against force-pushing" and "the server rejects a
// non-fast-forward push" are different facts with different security value, and
// only the second is `mechanism`. Recording `mechanism` because the rule exists
// — rather than because the probe came back positive — is precisely the theatre
// this feature exists to prevent, and it is worse than recording nothing,
// because it retires the question.
//
// Three outcomes, and the third is the one usually missed:
//
//	probe says protected      -> mechanism
//	probe says NOT protected  -> policy
//	probe could not run       -> SKIP with a reason, and NEITHER value
//
// An unprobeable remote yielding `policy` would be a quiet downgrade of an
// UNKNOWN into a claim (§11.4.6). Unknown is reported as unknown.
// ---------------------------------------------------------------------------

// ProtectionProbe reports whether the anchor location mechanically prevents
// rewriting. It returns an error when it could not find out — which is a third
// answer, not a false.
//
// The (bool, error) shape is deliberate: a probe that could only return a bool
// would have to fold "unreachable" into one of the two values, and whichever it
// chose would be a fabricated fact.
type ProtectionProbe func() (protected bool, err error)

// StrengthResult is one probe outcome. On SKIP, Strength is StrengthUnknown and
// Reason names why the probe could not decide.
type StrengthResult struct {
	Verdict  Verdict
	Strength string
	Reason   string
}

// ErrNoProbe is the reason recorded when no probe was supplied at all. A nil
// probe is not "no protection" — it is no evidence, and it skips.
var ErrNoProbe = errors.New("anchor: no protection probe was supplied")

// ProbeStrength runs probe and converts its outcome into a recordable strength.
//
// Note the direction of the default: absent POSITIVE evidence of mechanical
// prevention, the weaker claim. There is no branch in this function that can
// reach StrengthMechanism without probe having returned (true, nil), and that
// is the property the paired mutation attacks by defaulting the field to
// `mechanism`.
func ProbeStrength(probe ProtectionProbe) StrengthResult {
	if probe == nil {
		return StrengthResult{SKIP, StrengthUnknown, ErrNoProbe.Error()}
	}
	protected, err := probe()
	if err != nil {
		return StrengthResult{SKIP, StrengthUnknown, fmt.Sprintf(
			"the anchor remote could not be probed, so its strength is UNKNOWN and neither "+
				"value may be recorded: %v", err)}
	}
	if protected {
		return StrengthResult{PASS, StrengthMechanism,
			"probe verified that the anchor location mechanically refuses a non-fast-forward update"}
	}
	return StrengthResult{PASS, StrengthPolicy,
		"probe found no mechanical prevention of rewriting; the anchor is protected by policy only"}
}

// Strength-record errors, exported so callers can branch on the reason.
var (
	ErrStrengthOverstated = errors.New("anchor: recorded strength claims more than the probe found")
	ErrStrengthUnprobed   = errors.New("anchor: recorded strength claims a value the probe never established")
)

// ValidateRecordedStrength is the enforcement half: it is not enough that the
// probe is honest, the RECORD must match it.
//
// It is equally a FALSE-POSITIVE GUARD (§11.4.201(1)). The rule is "record what
// was probed", NOT "never say mechanism" — a validator that refuses a true
// claim is as wrong as one that accepts a false one, and a validator that
// refused every `mechanism` would pass a naive test while being useless.
func ValidateRecordedStrength(recorded string, probed StrengthResult) error {
	switch probed.Verdict {
	case PASS:
		if recorded != probed.Strength {
			return fmt.Errorf("%w: recorded %q, probe established %q (%s)",
				ErrStrengthOverstated, recorded, probed.Strength, probed.Reason)
		}
		return nil
	case SKIP:
		// The probe did not run. The ONLY honest record is unknown; both
		// `policy` and `mechanism` would convert an unknown into a fact.
		if recorded == StrengthUnknown || recorded == "" {
			return nil
		}
		return fmt.Errorf("%w: recorded %q against a probe that could not decide (%s)",
			ErrStrengthUnprobed, recorded, probed.Reason)
	default:
		return fmt.Errorf("%w: probe returned verdict %q, which establishes nothing (%s)",
			ErrStrengthUnprobed, probed.Verdict, probed.Reason)
	}
}

// ---------------------------------------------------------------------------
// A real probe for the git anchor remote.
// ---------------------------------------------------------------------------

// GitNonFastForwardProbe returns a ProtectionProbe that asks a git remote
// whether it mechanically refuses a non-fast-forward update.
//
// HONEST BOUNDARY (§11.4.6) — read this before using the result.
//
// There is no read-only git wire operation that reports a server's
// branch-protection configuration. `git ls-remote` proves the remote is
// REACHABLE and nothing more. Therefore this probe, as implemented, can return
// (false, nil) — "no evidence of mechanical prevention" — or an error, but it
// has NO path that returns (true, nil). Today's honest value on a plain git
// remote is `policy`, and that is not a placeholder to be optimised away: it is
// the measured fact.
//
// To legitimately reach `mechanism` a consumer must supply a probe that reads
// the hosting platform's protection API with credentials, or observes a real
// rejected non-fast-forward push. Both are operator-gated actions (a host
// boundary an agent is correctly forbidden from creating), so until an operator
// takes one, the system operates at the weaker strength and MUST say so.
func GitNonFastForwardProbe(remote string, timeout time.Duration) ProtectionProbe {
	return func() (bool, error) {
		if strings.TrimSpace(remote) == "" {
			return false, errors.New("no anchor remote was configured")
		}
		// Reachability first: an unreachable remote is UNKNOWN, not unprotected.
		// Without this, a network outage would silently be recorded as "policy",
		// which is a claim we did not earn.
		cmd := exec.Command("git", "ls-remote", "--exit-code", "--heads", remote)
		cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/true")

		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			return false, fmt.Errorf("could not run git ls-remote: %w", err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				return false, fmt.Errorf("remote %s is not reachable: %w", remote, err)
			}
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			<-done
			return false, fmt.Errorf("probing remote %s timed out after %s", remote, timeout)
		}

		// Reachable, and nothing observed that mechanically prevents rewriting.
		// This is the weaker claim, and it is the true one.
		return false, nil
	}
}
