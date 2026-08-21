// Command continuum-integrity exposes the evidence-chain and anchor mechanism
// to the shell seams (T323).
//
// Verbs:
//
//	chain verify    walk the evidence chain and report CHAIN-ALONE integrity
//	anchor write    record head_digest + entry_count + PROBED anchor_strength
//	anchor verify   compare a chain against its anchor (CHAIN-PLUS-ANCHOR)
//
// # This is an adapter, not an implementation (§11.4.251)
//
// Every decision below is made by a package and merely rendered here:
//
//	chain-alone walk .............. verify.VerifyChainFile
//	record decode / digest ........ chain.Decode / chain.Digest
//	anchor comparison ............. anchor.Check
//	anchor forward-only write ..... anchor.Write
//	strength probe + honesty ...... anchor.ProbeStrength / ValidateRecordedStrength
//
// There is deliberately NO chain walk, NO digest, NO head-digest comparison and
// NO prefix-first check in this file. Two of those would be outright forks; the
// other two would be worse than forks, because a head-digest-equality check or a
// prefix-before-count check COLLAPSES the lagging anchor into the truncated
// chain (see anchor.Check's own note). A lagging anchor — a chain that merely
// grew by valid appends — is HEALTHY, and refusing it is a FAIL-bluff exactly as
// serious as a false pass (§11.4.201(1)). If you are here to "simplify" the
// summariser into a head comparison: that is the named paired mutation for this
// mechanism, and it must make the lagging negative control fail.
//
// # The three verdicts stay three (§11.4/§11.4.201(6))
//
//	PASS      the check ran and the property holds.
//	DETECTED  the check ran and found a named alteration.
//	REFUSE    the check APPLIES here and could not decide. Blocking.
//	SKIP      the check does NOT apply here, with the reason named.
//
// Collapsing REFUSE into PASS is the exact bluff this whole feature exists to
// prevent: a walk that could not finish has decided nothing, and "undecided"
// rendered as "intact" is indistinguishable at the seam from a clean result.
// Collapsing it into DETECTED is the mirror error — it sends an operator to
// hunt a tamper when the real problem is a blind instrument.
//
// # A shell seam distinguishes them WITHOUT parsing prose
//
//	0  PASS
//	3  DETECTED
//	4  REFUSE
//	5  SKIP     (nothing applied — see below)
//	2  usage error
//	1  operational error (could not run at all)
//
// SKIP is deliberately NOT exit 0. Returning 0 for "I checked nothing" would let
// the common `if continuum-integrity chain verify; then deploy; fi` read an
// honest non-result as a verification — the §11.4.201(6) false-null, at the one
// seam where it would do the most damage. Whether a SKIP is acceptable is the
// SEAM's policy decision (§11.4.3), taken on an explicit code; this command does
// not grant it silently by exiting 0.
//
// # Machine-readable output
//
// A single JSON object on STDOUT, always carrying chain_alone and
// chain_plus_anchor as DISTINCT fields — the pair of results is the evidence
// that the ANCHOR, not the chain, carries the truncation property. Neither field
// is ever omitted: an absent field would be read as null, and null reads as
// clean. When a half does not apply it is present and SKIP, with the reason.
// A one-line human summary goes to STDERR so an operator can watch without
// breaking a parser.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/vasic-digital/continuum/pkg/anchor"
	"github.com/vasic-digital/continuum/pkg/chain"
	"github.com/vasic-digital/continuum/pkg/verify"
)

// Exit codes. See the package doc for why SKIP is not 0.
const (
	exitPASS     = 0
	exitError    = 1
	exitUsage    = 2
	exitDETECTED = 3
	exitREFUSE   = 4
	exitSKIP     = 5
)

// The wire vocabulary is DERIVED from the packages' own constants rather than
// restated, so there is nothing that can drift (§11.4.251). pkg/chain and
// pkg/anchor declare their own identically-valued sets; that they still agree is
// asserted by TestWireVocabularyMatchesPackages, which fails the moment any of
// the three renames a verdict.
const (
	vPASS     = string(verify.PASS)
	vDETECTED = string(verify.DETECTED)
	vREFUSE   = string(verify.REFUSE)
	vSKIP     = string(verify.SKIP)
)

// result is one check's outcome. Reason is populated for EVERY verdict,
// including PASS: a seam that logs only the verdict loses the evidence, and a
// SKIP or REFUSE with no reason is an unactionable non-answer.
type result struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// strengthResult carries the probed anchor strength alongside its verdict. The
// strength VALUE and the verdict are separate fields because they answer
// different questions: "what protection was established" and "was it
// established at all" (§11.4.6 — an unprobed remote yields `unknown`, which is
// a recorded absence of evidence, not a weak claim).
type strengthResult struct {
	Verdict  string `json:"verdict"`
	Strength string `json:"strength"`
	Reason   string `json:"reason"`
}

// report is the machine-readable object written to stdout.
type report struct {
	Command         string         `json:"command"`
	ChainPath       string         `json:"chain_path"`
	AnchorPath      string         `json:"anchor_path"`
	Verdict         string         `json:"verdict"`
	Reason          string         `json:"reason"`
	ChainAlone      result         `json:"chain_alone"`
	ChainPlusAnchor result         `json:"chain_plus_anchor"`
	AnchorStrength  strengthResult `json:"anchor_strength"`
	ExitCode        int            `json:"exit_code"`
}

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(exitUsage)
	}
	group, verb, args := os.Args[1], os.Args[2], os.Args[3:]

	var (
		rep report
		err error
	)
	switch group + " " + verb {
	case "chain verify":
		rep, err = cmdChainVerify(args)
	case "anchor write":
		rep, err = cmdAnchorWrite(args)
	case "anchor verify":
		rep, err = cmdAnchorVerify(args)
	default:
		fmt.Fprintf(os.Stderr, "continuum-integrity: unknown command %q\n\n", group+" "+verb)
		usage()
		os.Exit(exitUsage)
	}
	if err != nil {
		// An operational failure is NOT a verdict. Reporting it as REFUSE would
		// blur "the mechanism could not decide about your chain" into "the
		// mechanism could not be invoked", which are different problems with
		// different owners.
		fmt.Fprintln(os.Stderr, "continuum-integrity: "+err.Error())
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(exitUsage)
		}
		os.Exit(exitError)
	}
	os.Exit(emit(rep))
}

func usage() {
	fmt.Fprint(os.Stderr, `continuum-integrity — evidence-chain + anchor verification for shell seams

usage: continuum-integrity <group> <verb> [flags]

  chain verify   --chain <path>
        Walk the evidence chain and report CHAIN-ALONE integrity.
        Detects mutation, deletion and reorder. Does NOT detect tail
        truncation or deletion+full-re-chain — those leave a structurally
        valid chain and are the anchor's to catch, so chain_plus_anchor is
        reported SKIP here rather than silently omitted.

  anchor write   --chain <path> --anchor <path> [--remote <r>] [--probe-timeout <d>]
        Record head_digest + entry_count + PROBED anchor_strength, then read
        the anchor back and confirm it (11.4.200). Forward-only: a lower
        entry_count, or a rewrite of an already-anchored head, is refused.
        Without --remote the strength probe SKIPs and "unknown" is recorded —
        that is the honest value, not a placeholder (11.4.6).

  anchor verify  --chain <path> --anchor <path> [--remote <r>] [--probe-timeout <d>]
        Compare the chain against its anchor and report chain_alone and
        chain_plus_anchor as distinct results. --remote additionally
        cross-checks the anchor's RECORDED strength against a live probe; it
        is opt-in because a stale-but-honest strength would otherwise block a
        seam that never asked about strength.

paths: --chain or CONTINUUM_CHAIN, --anchor or CONTINUUM_ANCHOR (no default;
       the command fails closed rather than guess a project path, 11.4.6)

exit:  0 PASS | 3 DETECTED | 4 REFUSE | 5 SKIP | 2 usage | 1 operational error
       SKIP is not 0 on purpose: "I checked nothing" must not read as "verified".
`)
}

// emit writes the JSON report to stdout, a human line to stderr, and returns
// the exit code for the overall verdict.
func emit(rep report) int {
	rep.ExitCode = codeFor(rep.Verdict)
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		// Failing to render the report is an operational failure, and it must
		// not masquerade as a verdict.
		fmt.Fprintln(os.Stderr, "continuum-integrity: rendering report: "+err.Error())
		return exitError
	}
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "%s [%s] chain_alone=%s chain_plus_anchor=%s: %s\n",
		rep.Command, rep.Verdict, rep.ChainAlone.Verdict, rep.ChainPlusAnchor.Verdict, rep.Reason)
	return rep.ExitCode
}

func codeFor(v string) int {
	switch v {
	case vPASS:
		return exitPASS
	case vDETECTED:
		return exitDETECTED
	case vREFUSE:
		return exitREFUSE
	case vSKIP:
		return exitSKIP
	default:
		// An unrecognised verdict has decided nothing, so it must not exit 0
		// (§11.4.252 fail closed). REFUSE is the honest code for it.
		return exitREFUSE
	}
}

// rank orders the verdicts for aggregation.
//
// DETECTED outranks REFUSE deliberately. Both block, so the ordering does not
// change whether a seam proceeds — it changes what the operator is told, and a
// positive detection is strictly more actionable than an undecided one. The
// refusal is not lost: it stays verbatim in its own field, including the
// "records beyond this point are UNVERIFIED" caveat.
func rank(v string) int {
	switch v {
	case vDETECTED:
		return 4
	case vREFUSE:
		return 3
	case vPASS:
		return 2
	case vSKIP:
		return 1
	default:
		// Unknown outranks everything: an unrecognised verdict must never be
		// averaged away into a PASS.
		return 5
	}
}

// overall aggregates the sub-results, naming which one drove the outcome.
func overall(named ...struct {
	name string
	res  result
}) (string, string) {
	if len(named) == 0 {
		return vREFUSE, "no checks ran, so nothing was decided"
	}
	best := named[0]
	for _, n := range named[1:] {
		if rank(n.res.Verdict) > rank(best.res.Verdict) {
			best = n
		}
	}
	return best.res.Verdict, fmt.Sprintf("%s is %s: %s", best.name, best.res.Verdict, best.res.Reason)
}

func agg(chainAlone, chainPlusAnchor result) (string, string) {
	type nr = struct {
		name string
		res  result
	}
	return overall(nr{"chain_alone", chainAlone}, nr{"chain_plus_anchor", chainPlusAnchor})
}

// ---- path resolution -------------------------------------------------------

// resolvePath fails CLOSED when neither the flag nor the environment supplies a
// path. Guessing a project path is exactly the kind of invented fact §11.4.6
// forbids, and a verifier pointed at the wrong file is worse than no verifier.
func resolvePath(flagVal, env, what string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no %s path: pass --%s or set $%s (this command will not guess one)", what, what, env)
}

// ---- shared pieces ---------------------------------------------------------

// summarise builds the anchor's view of a chain: head digest, count, and the
// digest of any prefix.
//
// It computes NOTHING itself — every digest is chain.Digest, the module's one
// digest, so a summary built here and one built anywhere else are identical by
// construction. anchor.Check needs the prefix accessor to tell a LAGGING anchor
// (the chain grew) from a TRUNCATED chain (the chain shrank); without it Check
// refuses, and with a head comparison substituted for it Check would condemn
// both.
func summarise(recs []chain.Record) (anchor.ChainSummary, error) {
	head := ""
	if len(recs) > 0 {
		d, err := chain.Digest(recs[len(recs)-1])
		if err != nil {
			return anchor.ChainSummary{}, fmt.Errorf("digesting chain head: %w", err)
		}
		head = d
	}
	return anchor.ChainSummary{
		Head:  head,
		Count: len(recs),
		PrefixHead: func(n int) (string, error) {
			if n <= 0 || n > len(recs) {
				return "", anchor.ErrPrefixUnavailable
			}
			return chain.Digest(recs[n-1])
		},
	}, nil
}

// loadChain reads and decodes the chain, converting every failure into a REFUSE
// reason rather than an error, so an unreadable chain is a verdict a seam can
// act on. It never returns records AND a refusal.
func loadChain(path string) ([]chain.Record, *result) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &result{vREFUSE, fmt.Sprintf(
			"chain store %q could not be read, so the anchor comparison never started and "+
				"decided nothing: %v", path, err)}
	}
	recs, err := chain.Decode(b)
	if err != nil {
		return nil, &result{vREFUSE, fmt.Sprintf(
			"chain store %q could not be decoded, so it cannot be summarised for the anchor: %v — "+
				"this is an undecided result, not a clean one", path, err)}
	}
	return recs, nil
}

// probe builds the strength probe. A remote that was not named yields a NIL
// probe, and a nil probe is not "no protection" — it is no evidence, which
// anchor.ProbeStrength records as SKIP/unknown.
func probeFor(remote string, timeout time.Duration) anchor.ProtectionProbe {
	if remote == "" {
		return nil
	}
	return anchor.GitNonFastForwardProbe(remote, timeout)
}

func toStrengthResult(sr anchor.StrengthResult) strengthResult {
	return strengthResult{string(sr.Verdict), sr.Strength, sr.Reason}
}

// ---- chain verify ----------------------------------------------------------

func cmdChainVerify(args []string) (report, error) {
	fs := flag.NewFlagSet("chain verify", flag.ContinueOnError)
	chainFlag := fs.String("chain", "", "path to the evidence chain (JSONL) (or $CONTINUUM_CHAIN)")
	if err := fs.Parse(args); err != nil {
		return report{}, err
	}
	chainPath, err := resolvePath(*chainFlag, "CONTINUUM_CHAIN", "chain")
	if err != nil {
		return report{}, err
	}

	ca := verify.VerifyChainFile(chainPath)
	rep := report{
		Command:    "chain verify",
		ChainPath:  chainPath,
		ChainAlone: result{string(ca.Verdict), ca.Detail},
		// Reported, never omitted. This half genuinely does not apply — no
		// anchor was asked for — and saying so out loud is what stops a
		// chain-alone PASS being read as "the chain is complete". It is not:
		// tail truncation and deletion+full-re-chain both PASS here by design.
		ChainPlusAnchor: result{vSKIP, "no anchor was supplied, so completeness was NOT checked; " +
			"a chain-alone PASS means the records present are internally consistent, NOT that the " +
			"chain is complete — run `anchor verify` for that"},
		AnchorStrength: strengthResult{vSKIP, anchor.StrengthUnknown,
			"anchor strength is not examined by `chain verify`"},
	}
	// The SKIP half must not drag the outcome down, and the chain half must not
	// be able to hide behind it: aggregation ranks SKIP lowest for exactly this.
	rep.Verdict, rep.Reason = agg(rep.ChainAlone, rep.ChainPlusAnchor)
	return rep, nil
}

// ---- anchor verify ---------------------------------------------------------

func cmdAnchorVerify(args []string) (report, error) {
	fs := flag.NewFlagSet("anchor verify", flag.ContinueOnError)
	chainFlag := fs.String("chain", "", "path to the evidence chain (JSONL) (or $CONTINUUM_CHAIN)")
	anchorFlag := fs.String("anchor", "", "path to the anchor record (or $CONTINUUM_ANCHOR)")
	remote := fs.String("remote", "", "git remote to cross-check the RECORDED anchor_strength against (opt-in)")
	timeout := fs.Duration("probe-timeout", 10*time.Second, "timeout for the strength probe")
	if err := fs.Parse(args); err != nil {
		return report{}, err
	}
	chainPath, err := resolvePath(*chainFlag, "CONTINUUM_CHAIN", "chain")
	if err != nil {
		return report{}, err
	}
	anchorPath, err := resolvePath(*anchorFlag, "CONTINUUM_ANCHOR", "anchor")
	if err != nil {
		return report{}, err
	}

	rep := report{Command: "anchor verify", ChainPath: chainPath, AnchorPath: anchorPath}

	// Half 1 — chain-alone. Reported in full even when the anchor half decides
	// the outcome: the PAIR is the evidence for which layer carries which
	// property, and a seam that only ever saw the aggregate could not tell a
	// mutated chain from a truncated one.
	ca := verify.VerifyChainFile(chainPath)
	rep.ChainAlone = result{string(ca.Verdict), ca.Detail}

	// Half 2 — chain-plus-anchor.
	rep.ChainPlusAnchor = anchorHalf(chainPath, anchorPath)

	// Optional third — is the RECORDED strength what a live probe finds?
	rep.AnchorStrength = strengthHalf(anchorPath, *remote, *timeout)

	rep.Verdict, rep.Reason = agg(rep.ChainAlone, rep.ChainPlusAnchor)
	// The strength cross-check only participates when it was actually asked
	// for. Letting an opt-in check block a seam that never opted in would be a
	// false refusal (§11.4.201(1)).
	if *remote != "" {
		type nr = struct {
			name string
			res  result
		}
		rep.Verdict, rep.Reason = overall(
			nr{"chain_alone", rep.ChainAlone},
			nr{"chain_plus_anchor", rep.ChainPlusAnchor},
			nr{"anchor_strength", result{rep.AnchorStrength.Verdict, rep.AnchorStrength.Reason}},
		)
	}
	return rep, nil
}

// anchorHalf performs the chain-plus-anchor comparison. Every decision is
// anchor.Check's; this function only obtains its two inputs and converts the
// failures to obtain them into refusals.
func anchorHalf(chainPath, anchorPath string) result {
	a, err := anchor.Read(anchorPath)
	if err != nil {
		// An ABSENT anchor refuses; it does not skip. The seam asked to compare
		// against an anchor, and "there is no anchor" is precisely the state a
		// wholesale deletion produces — reporting it as an inapplicable check
		// would hand the attacker the verdict.
		return result{vREFUSE, fmt.Sprintf(
			"anchor %q could not be read, so the chain was compared against nothing: %v — "+
				"an absent or unreadable anchor is undecided, never verified", anchorPath, err)}
	}
	recs, ref := loadChain(chainPath)
	if ref != nil {
		return *ref
	}
	cs, err := summarise(recs)
	if err != nil {
		return result{vREFUSE, fmt.Sprintf(
			"chain %q could not be summarised for comparison: %v", chainPath, err)}
	}
	r := anchor.Check(a, cs)
	return result{string(r.Verdict), r.Reason}
}

// strengthHalf cross-checks the RECORDED strength against a live probe.
//
// Opt-in by design. anchor.ValidateRecordedStrength enforces "record what was
// probed" strictly in BOTH directions, so an anchor written without a probe
// (honestly recording `unknown`) does not match a later probe that establishes
// `policy`. That mismatch is real and worth surfacing — the anchor's strength
// record is stale — but it is not a chain integrity problem, and making every
// routine verification block on it would be the false refusal §11.4.201(1)
// names. So a seam has to ask.
func strengthHalf(anchorPath, remote string, timeout time.Duration) strengthResult {
	if remote == "" {
		return strengthResult{vSKIP, anchor.StrengthUnknown,
			"no --remote was given, so the recorded anchor_strength was NOT cross-checked " +
				"against a live probe (opt-in)"}
	}
	a, err := anchor.Read(anchorPath)
	if err != nil {
		return strengthResult{vREFUSE, anchor.StrengthUnknown, fmt.Sprintf(
			"anchor %q could not be read, so its recorded strength could not be cross-checked: %v",
			anchorPath, err)}
	}
	probed := anchor.ProbeStrength(probeFor(remote, timeout))
	if err := anchor.ValidateRecordedStrength(a.Strength, probed); err != nil {
		return strengthResult{vDETECTED, probed.Strength, fmt.Sprintf(
			"the anchor's recorded strength does not match the probe: %v", err)}
	}
	return strengthResult{vPASS, probed.Strength, fmt.Sprintf(
		"the anchor's recorded strength %q matches the probe: %s", a.Strength, probed.Reason)}
}

// ---- anchor write ----------------------------------------------------------

func cmdAnchorWrite(args []string) (report, error) {
	fs := flag.NewFlagSet("anchor write", flag.ContinueOnError)
	chainFlag := fs.String("chain", "", "path to the evidence chain (JSONL) (or $CONTINUUM_CHAIN)")
	anchorFlag := fs.String("anchor", "", "path to the anchor record to write (or $CONTINUUM_ANCHOR)")
	remote := fs.String("remote", "", "git remote to probe for non-fast-forward protection")
	timeout := fs.Duration("probe-timeout", 10*time.Second, "timeout for the strength probe")
	if err := fs.Parse(args); err != nil {
		return report{}, err
	}
	chainPath, err := resolvePath(*chainFlag, "CONTINUUM_CHAIN", "chain")
	if err != nil {
		return report{}, err
	}
	anchorPath, err := resolvePath(*anchorFlag, "CONTINUUM_ANCHOR", "anchor")
	if err != nil {
		return report{}, err
	}

	rep := report{
		Command:    "anchor write",
		ChainPath:  chainPath,
		AnchorPath: anchorPath,
		// Writing is not comparing. Saying so explicitly stops a green write
		// being mistaken for a verification of the chain it just anchored.
		ChainPlusAnchor: result{vSKIP,
			"`anchor write` records an anchor, it does not compare against one; run `anchor verify`"},
	}

	// The strength is PROBED, never assumed (FR-038). Without a remote the
	// probe SKIPs and `unknown` is recorded — the measured fact, not a
	// placeholder to be optimised into `policy` later.
	probed := anchor.ProbeStrength(probeFor(*remote, *timeout))
	rep.AnchorStrength = toStrengthResult(probed)

	recs, ref := loadChain(chainPath)
	if ref != nil {
		rep.ChainAlone = *ref
		rep.Verdict, rep.Reason = rep.ChainAlone.Verdict, rep.ChainAlone.Reason
		return rep, nil
	}

	// Anchoring a chain that is itself broken would record a tampered state as
	// the expected one. The walk is cheap (100k entries measured at 0.21 s), so
	// there is no argument for skipping it here.
	ca := verify.VerifyChainFile(chainPath)
	rep.ChainAlone = result{string(ca.Verdict), ca.Detail}
	if ca.Verdict != verify.PASS {
		rep.Verdict, rep.Reason = rep.ChainAlone.Verdict, fmt.Sprintf(
			"refusing to anchor a chain that does not verify chain-alone (%s): %s",
			ca.Verdict, ca.Detail)
		if rep.Verdict == vPASS {
			rep.Verdict = vREFUSE
		}
		return rep, nil
	}

	cs, err := summarise(recs)
	if err != nil {
		rep.Verdict, rep.Reason = vREFUSE, fmt.Sprintf("chain %q could not be summarised: %v", chainPath, err)
		return rep, nil
	}

	next := anchor.Anchor{HeadDigest: cs.Head, EntryCount: cs.Count, Strength: probed.Strength}
	if err := anchor.Write(anchorPath, next); err != nil {
		rep.Verdict, rep.Reason = classifyWriteError(anchorPath, err)
		return rep, nil
	}

	// Verify-after-write against the INTENDED target (§11.4.200). The writer's
	// own success return proves the call returned, not that the bytes on disk
	// say what we meant; only reading them back does.
	back, err := anchor.Read(anchorPath)
	if err != nil {
		rep.Verdict, rep.Reason = vREFUSE, fmt.Sprintf(
			"the anchor was written to %q but could not be read back, so it is unconfirmed: %v",
			anchorPath, err)
		return rep, nil
	}
	if back != next {
		rep.Verdict, rep.Reason = vDETECTED, fmt.Sprintf(
			"the anchor read back from %q is not the one written (wrote head=%s count=%d strength=%q; "+
				"read head=%s count=%d strength=%q)",
			anchorPath, next.HeadDigest, next.EntryCount, next.Strength,
			back.HeadDigest, back.EntryCount, back.Strength)
		return rep, nil
	}

	rep.Verdict = vPASS
	rep.Reason = fmt.Sprintf(
		"anchored %d entries at head %s with strength %q, read back and confirmed at %q",
		back.EntryCount, back.HeadDigest, back.Strength, anchorPath)
	return rep, nil
}

// classifyWriteError separates a DIVERGENCE from an INABILITY.
//
// anchor.Write reads the anchor already on disk and compares before writing, so
// a regression or a rewrite is a comparison that FOUND something: the state
// being offered is not a forward extension of the state already anchored, which
// is the signature of a truncated or rewritten chain. Reporting that as REFUSE
// would understate a real finding. Every other failure — validation, I/O — is an
// inability to complete, which is REFUSE.
func classifyWriteError(path string, err error) (string, string) {
	switch {
	case errors.Is(err, anchor.ErrAnchorRegression):
		return vDETECTED, fmt.Sprintf(
			"refused to move the anchor at %q backwards: %v — the chain being anchored is SHORTER "+
				"than the one already anchored, which is the tail-truncation signature", path, err)
	case errors.Is(err, anchor.ErrAnchorRewrite):
		return vDETECTED, fmt.Sprintf(
			"refused to rewrite the already-anchored state at %q: %v — the same entry_count now "+
				"hashes differently, which is the history-rewrite signature", path, err)
	default:
		return vREFUSE, fmt.Sprintf("the anchor at %q could not be written: %v", path, err)
	}
}
