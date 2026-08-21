package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasic-digital/continuum/pkg/anchor"
	"github.com/vasic-digital/continuum/pkg/chain"
	"github.com/vasic-digital/continuum/pkg/verify"
)

// ---- fixtures --------------------------------------------------------------

// healthy writes a real n-record chain using the package builder, so the
// negative controls below are the SAME artifact the unit tests and any gate
// use. A private builder here would be the fork §11.4.251 forbids.
func healthy(t *testing.T, path string, n int) {
	t.Helper()
	if err := verify.WriteHealthyChainForTest(path, n); err != nil {
		t.Fatalf("building healthy chain of %d: %v", n, err)
	}
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func writeLines(t *testing.T, path string, ls []string) {
	t.Helper()
	body := ""
	if len(ls) > 0 {
		body = strings.Join(ls, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// reorder swaps two adjacent records. That is a REAL attack (T304), and it is
// used instead of field surgery because a swap cannot accidentally produce a
// line that fails to decode — which would silently turn a DETECTED test into a
// REFUSE test and stop proving what it claims to prove.
func reorder(t *testing.T, path string, i int) {
	t.Helper()
	ls := lines(t, path)
	if i < 0 || i+1 >= len(ls) {
		t.Fatalf("reorder: index %d out of range for %d lines", i, len(ls))
	}
	ls[i], ls[i+1] = ls[i+1], ls[i]
	writeLines(t, path, ls)
}

// truncateRecords removes whole records from the END. What remains is a
// STRUCTURALLY VALID chain, which is the entire point: chain-alone must PASS it
// and only the anchor can catch it.
func truncateRecords(t *testing.T, path string, keep int) {
	t.Helper()
	ls := lines(t, path)
	if keep > len(ls) {
		t.Fatalf("truncateRecords: keep=%d exceeds %d lines", keep, len(ls))
	}
	writeLines(t, path, ls[:keep])
}

// cutMidRecord truncates the file mid-line, leaving a half-written record. That
// is a different failure from removing whole records and must REFUSE, not PASS:
// collapsing the two would either refuse every legitimately shortened chain or
// silently accept a torn write.
func cutMidRecord(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if len(b) < 40 {
		t.Fatalf("chain too small to cut: %d bytes", len(b))
	}
	if err := os.WriteFile(path, b[:len(b)-20], 0o644); err != nil {
		t.Fatalf("cutting %s: %v", path, err)
	}
}

func mustAnchor(t *testing.T, chainPath, anchorPath string) report {
	t.Helper()
	rep, err := cmdAnchorWrite([]string{"--chain", chainPath, "--anchor", anchorPath})
	if err != nil {
		t.Fatalf("anchor write: %v", err)
	}
	if rep.Verdict != vPASS {
		t.Fatalf("anchor write should PASS on a healthy chain, got %s: %s", rep.Verdict, rep.Reason)
	}
	return rep
}

// ---- vocabulary + exit codes ----------------------------------------------

// The wire vocabulary is derived from pkg/verify. pkg/chain and pkg/anchor
// declare their own identically-valued sets, and a shell seam parses ONE
// vocabulary, so this test fails the moment any of the three drifts.
func TestWireVocabularyMatchesPackages(t *testing.T) {
	for _, c := range []struct{ name, wire, got string }{
		{"chain.PASS", vPASS, string(chain.PASS)},
		{"chain.DETECTED", vDETECTED, string(chain.DETECTED)},
		{"chain.REFUSE", vREFUSE, string(chain.REFUSE)},
		{"anchor.PASS", vPASS, string(anchor.PASS)},
		{"anchor.DETECTED", vDETECTED, string(anchor.DETECTED)},
		{"anchor.REFUSE", vREFUSE, string(anchor.REFUSE)},
		{"anchor.SKIP", vSKIP, string(anchor.SKIP)},
		{"verify.PASS", vPASS, string(verify.PASS)},
		{"verify.DETECTED", vDETECTED, string(verify.DETECTED)},
		{"verify.REFUSE", vREFUSE, string(verify.REFUSE)},
		{"verify.SKIP", vSKIP, string(verify.SKIP)},
	} {
		if c.wire != c.got {
			t.Errorf("%s = %q but the wire vocabulary says %q; a seam parsing one would misread the other",
				c.name, c.got, c.wire)
		}
	}
}

// A seam must tell the verdicts apart from the exit code alone, without parsing
// prose. SKIP being 0 is called out separately because that is the specific
// false-null this command exists to avoid.
func TestExitCodesAreDistinctAndSkipIsNotZero(t *testing.T) {
	codes := map[string]int{
		vPASS:     codeFor(vPASS),
		vDETECTED: codeFor(vDETECTED),
		vREFUSE:   codeFor(vREFUSE),
		vSKIP:     codeFor(vSKIP),
	}
	seen := map[int]string{}
	for v, c := range codes {
		if prev, dup := seen[c]; dup {
			t.Errorf("%s and %s both exit %d: a seam cannot tell them apart", prev, v, c)
		}
		seen[c] = v
	}
	if codes[vPASS] != 0 {
		t.Errorf("PASS must exit 0, got %d", codes[vPASS])
	}
	for _, v := range []string{vDETECTED, vREFUSE, vSKIP} {
		if codes[v] == 0 {
			t.Errorf("%s must NOT exit 0: a seam using `if cmd; then deploy; fi` would read it as verified", v)
		}
	}
	// An unrecognised verdict has decided nothing and must fail closed.
	if got := codeFor("SOMETHING_NEW"); got == 0 {
		t.Errorf("an unrecognised verdict must not exit 0, got %d", got)
	}
}

// The aggregate must never let a real finding hide behind a SKIP, and a SKIP
// must never drag a healthy result down.
func TestAggregation(t *testing.T) {
	for _, c := range []struct{ name, a, b, want string }{
		{"pass+skip", vPASS, vSKIP, vPASS},
		{"skip+pass", vSKIP, vPASS, vPASS},
		{"skip+skip", vSKIP, vSKIP, vSKIP},
		{"pass+detected", vPASS, vDETECTED, vDETECTED},
		{"pass+refuse", vPASS, vREFUSE, vREFUSE},
		{"refuse+detected", vREFUSE, vDETECTED, vDETECTED},
		{"detected+refuse", vDETECTED, vREFUSE, vDETECTED},
	} {
		got, reason := agg(result{c.a, "a"}, result{c.b, "b"})
		if got != c.want {
			t.Errorf("%s: aggregate = %s, want %s", c.name, got, c.want)
		}
		if reason == "" {
			t.Errorf("%s: aggregate reason is empty; a verdict with no reason is unactionable", c.name)
		}
	}
}

// ---- chain verify ----------------------------------------------------------

// FALSE-POSITIVE GUARD (§11.4.201(1)): a verifier that refuses everything
// satisfies every refusal assertion above and is useless.
func TestChainVerify_HealthyChainPASSes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	healthy(t, p, 8)

	rep, err := cmdChainVerify([]string{"--chain", p})
	if err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vPASS {
		t.Fatalf("chain_alone = %s on a healthy chain, want PASS: %s", rep.ChainAlone.Verdict, rep.ChainAlone.Reason)
	}
	if rep.Verdict != vPASS {
		t.Errorf("overall = %s, want PASS: %s", rep.Verdict, rep.Reason)
	}
	// The completeness limit must be stated, not implied by silence.
	if rep.ChainPlusAnchor.Verdict != vSKIP {
		t.Errorf("chain_plus_anchor = %s with no anchor supplied, want SKIP", rep.ChainPlusAnchor.Verdict)
	}
	if rep.ChainPlusAnchor.Reason == "" {
		t.Error("a SKIP with no reason is an unactionable non-answer")
	}
}

func TestChainVerify_ReorderDETECTED(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	healthy(t, p, 8)
	reorder(t, p, 2)

	rep, err := cmdChainVerify([]string{"--chain", p})
	if err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vDETECTED {
		t.Fatalf("chain_alone = %s on a reordered chain, want DETECTED: %s",
			rep.ChainAlone.Verdict, rep.ChainAlone.Reason)
	}
	if rep.Verdict != vDETECTED {
		t.Errorf("overall = %s, want DETECTED", rep.Verdict)
	}
}

// An absent store is the wholesale-deletion case. "There is nothing here" must
// never read as "nothing is wrong".
func TestChainVerify_AbsentChainREFUSES(t *testing.T) {
	p := filepath.Join(t.TempDir(), "does-not-exist.jsonl")

	rep, err := cmdChainVerify([]string{"--chain", p})
	if err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if rep.Verdict != vREFUSE {
		t.Fatalf("overall = %s on an absent chain, want REFUSE: %s", rep.Verdict, rep.Reason)
	}
	if rep.Verdict == vPASS {
		t.Fatal("an absent chain reported as PASS is the exact bluff this command exists to prevent")
	}
}

// A half-written record stops the walk, leaving everything beyond it
// unverified. That is undecided, not clean.
func TestChainVerify_MalformedChainREFUSES(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	healthy(t, p, 8)
	cutMidRecord(t, p)

	rep, err := cmdChainVerify([]string{"--chain", p})
	if err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vREFUSE {
		t.Fatalf("chain_alone = %s on a torn write, want REFUSE: %s",
			rep.ChainAlone.Verdict, rep.ChainAlone.Reason)
	}
}

// Guessing a path is an invented fact; the command must fail closed instead.
func TestChainVerify_NoPathFailsClosed(t *testing.T) {
	t.Setenv("CONTINUUM_CHAIN", "")
	if _, err := cmdChainVerify(nil); err == nil {
		t.Fatal("chain verify with no --chain and no $CONTINUUM_CHAIN must fail, not guess a path")
	}
}

func TestChainVerify_PathFromEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	healthy(t, p, 3)
	t.Setenv("CONTINUUM_CHAIN", p)

	rep, err := cmdChainVerify(nil)
	if err != nil {
		t.Fatalf("chain verify from env: %v", err)
	}
	if rep.ChainPath != p || rep.Verdict != vPASS {
		t.Fatalf("env path not honoured: path=%q verdict=%s", rep.ChainPath, rep.Verdict)
	}
}

// Both halves must be PRESENT in the JSON for every command. An omitted field
// decodes to a zero value, and a zero value reads as neither a verdict nor a
// refusal — which is how a non-result gets mistaken for a clean one.
func TestReportAlwaysCarriesBothHalves(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")
	healthy(t, cp, 4)

	reps := map[string]report{}
	r1, err := cmdChainVerify([]string{"--chain", cp})
	if err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	reps["chain verify"] = r1
	reps["anchor write"] = mustAnchor(t, cp, ap)
	r3, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	reps["anchor verify"] = r3

	for name, rep := range reps {
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatalf("%s: marshalling: %v", name, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: unmarshalling: %v", name, err)
		}
		for _, field := range []string{"verdict", "reason", "chain_alone", "chain_plus_anchor", "anchor_strength", "exit_code"} {
			if _, ok := m[field]; !ok {
				t.Errorf("%s: field %q is absent from the JSON; an absent field reads as null, and null reads as clean", name, field)
			}
		}
		for _, half := range []struct {
			name string
			res  result
		}{{"chain_alone", rep.ChainAlone}, {"chain_plus_anchor", rep.ChainPlusAnchor}} {
			if half.res.Verdict == "" {
				t.Errorf("%s: %s carries an empty verdict", name, half.name)
			}
			if half.res.Reason == "" {
				t.Errorf("%s: %s carries no reason", name, half.name)
			}
		}
	}
}

// ---- anchor write ----------------------------------------------------------

func TestAnchorWrite_WritesProbesAndReadsBack(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "sub", "anchor.json")
	healthy(t, cp, 6)

	rep := mustAnchor(t, cp, ap)

	// No --remote was given, so the strength is UNKNOWN and says so. Recording
	// `policy` here would convert an absence of evidence into a claim.
	if rep.AnchorStrength.Verdict != vSKIP {
		t.Errorf("strength probe = %s with no --remote, want SKIP", rep.AnchorStrength.Verdict)
	}
	if rep.AnchorStrength.Strength != anchor.StrengthUnknown {
		t.Errorf("strength = %q with no probe, want %q", rep.AnchorStrength.Strength, anchor.StrengthUnknown)
	}

	a, err := anchor.Read(ap)
	if err != nil {
		t.Fatalf("reading the anchor back: %v", err)
	}
	if a.EntryCount != 6 {
		t.Errorf("entry_count = %d, want 6", a.EntryCount)
	}
	if a.HeadDigest == "" {
		t.Error("head_digest is empty; wholesale deletion would be undetectable")
	}
	if a.Strength != anchor.StrengthUnknown {
		t.Errorf("recorded strength = %q, want %q", a.Strength, anchor.StrengthUnknown)
	}
	// Re-running must be safe (the writer is idempotent for an identical anchor).
	mustAnchor(t, cp, ap)
}

// You do not anchor an empty chain: a count of 0 would hand an adversary who
// deleted the store an internally consistent pair.
func TestAnchorWrite_EmptyChainRefused(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")
	healthy(t, cp, 0)

	rep, err := cmdAnchorWrite([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor write: %v", err)
	}
	if rep.Verdict == vPASS {
		t.Fatal("anchoring an empty chain must not PASS")
	}
	if _, err := os.Stat(ap); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused write must leave no anchor behind; stat = %v", err)
	}
}

func TestAnchorWrite_BrokenChainNotAnchored(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")
	healthy(t, cp, 8)
	reorder(t, cp, 3)

	rep, err := cmdAnchorWrite([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor write: %v", err)
	}
	if rep.Verdict != vDETECTED {
		t.Fatalf("verdict = %s anchoring a broken chain, want DETECTED: %s", rep.Verdict, rep.Reason)
	}
	if _, err := os.Stat(ap); !errors.Is(err, os.ErrNotExist) {
		t.Error("a broken chain must not get anchored: recording it would make the tamper the expected state")
	}
}

// Dragging the anchor backwards to match a shorter chain is the truncation
// signature, and the writer compared before refusing — so this is a DETECTION,
// not a mere inability to act.
func TestAnchorWrite_RegressionDETECTED(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")

	healthy(t, cp, 8)
	mustAnchor(t, cp, ap)

	truncateRecords(t, cp, 5)
	rep, err := cmdAnchorWrite([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor write: %v", err)
	}
	if rep.Verdict != vDETECTED {
		t.Fatalf("verdict = %s re-anchoring a truncated chain, want DETECTED: %s", rep.Verdict, rep.Reason)
	}
	// The anchor on disk must be untouched.
	a, err := anchor.Read(ap)
	if err != nil {
		t.Fatalf("reading the anchor: %v", err)
	}
	if a.EntryCount != 8 {
		t.Errorf("anchor was moved backwards to %d; it must still record 8", a.EntryCount)
	}
}

// ---- anchor verify ---------------------------------------------------------

// THE FALSE-POSITIVE GUARD. A chain that merely grew by valid appends is
// HEALTHY. A head-digest-equality check would refuse it, and that refusal is a
// FAIL-bluff exactly as serious as a false pass: it condemns correct work.
func TestAnchorVerify_LaggingAnchorPASSes(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")

	healthy(t, cp, 5)
	mustAnchor(t, cp, ap)
	healthy(t, cp, 9) // valid appends: the first 5 records are unchanged

	rep, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vPASS {
		t.Errorf("chain_alone = %s, want PASS: %s", rep.ChainAlone.Verdict, rep.ChainAlone.Reason)
	}
	if rep.ChainPlusAnchor.Verdict != vPASS {
		t.Fatalf("chain_plus_anchor = %s on a LAGGING anchor, want PASS: %s",
			rep.ChainPlusAnchor.Verdict, rep.ChainPlusAnchor.Reason)
	}
	if rep.Verdict != vPASS {
		t.Errorf("overall = %s, want PASS: %s", rep.Verdict, rep.Reason)
	}
}

// THE PAIR. chain-alone PASSes a truncated chain by design; only the anchor
// catches it. Reporting them as one number would destroy the evidence that the
// ANCHOR carries this property.
func TestAnchorVerify_TruncationChainAlonePASSes_AnchorDETECTS(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")

	healthy(t, cp, 9)
	mustAnchor(t, cp, ap)
	truncateRecords(t, cp, 4)

	rep, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vPASS {
		t.Fatalf("chain_alone = %s on a truncated chain, want PASS (the documented limit): %s",
			rep.ChainAlone.Verdict, rep.ChainAlone.Reason)
	}
	if rep.ChainPlusAnchor.Verdict != vDETECTED {
		t.Fatalf("chain_plus_anchor = %s on a truncated chain, want DETECTED: %s",
			rep.ChainPlusAnchor.Verdict, rep.ChainPlusAnchor.Reason)
	}
	if rep.Verdict != vDETECTED {
		t.Errorf("overall = %s, want DETECTED", rep.Verdict)
	}
}

// A REWRITE of the anchored history, caught by the PREFIX comparison rather
// than by the count.
//
// The construction matters. Swapping two records without re-chaining leaves
// every LATER record byte-identical, so if the anchored position is beyond the
// swap the prefix digest does not move and the anchor correctly reports PASS —
// that reorder is the CHAIN's to detect, not the anchor's. To exercise the
// prefix comparison the record AT the anchored position must itself change, so
// the swap straddles it: the anchor recorded 5 entries, and position 5 now
// holds what used to be position 4.
func TestAnchorVerify_AnchoredPrefixRewriteDETECTED(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")

	healthy(t, cp, 5)
	mustAnchor(t, cp, ap)
	healthy(t, cp, 9) // count now exceeds the anchor, so the count path cannot fire
	reorder(t, cp, 3) // swaps positions 4 and 5 — the anchored position changes

	rep, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	if rep.ChainPlusAnchor.Verdict != vDETECTED {
		t.Fatalf("chain_plus_anchor = %s on a rewritten anchored prefix, want DETECTED: %s",
			rep.ChainPlusAnchor.Verdict, rep.ChainPlusAnchor.Reason)
	}
	if !strings.Contains(rep.ChainPlusAnchor.Reason, "rewritten") {
		t.Errorf("the reason should name the rewrite so an operator can act on it, got: %s",
			rep.ChainPlusAnchor.Reason)
	}
}

// An absent anchor REFUSES; it does not skip. The seam asked to compare against
// an anchor, and "there is no anchor" is exactly what wholesale deletion looks
// like — reporting it as inapplicable would hand the attacker the verdict.
func TestAnchorVerify_AbsentAnchorREFUSES(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	healthy(t, cp, 5)

	rep, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", filepath.Join(dir, "nope.json")})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vPASS {
		t.Errorf("chain_alone = %s, want PASS (only the anchor half is missing)", rep.ChainAlone.Verdict)
	}
	if rep.ChainPlusAnchor.Verdict != vREFUSE {
		t.Fatalf("chain_plus_anchor = %s with no anchor on disk, want REFUSE: %s",
			rep.ChainPlusAnchor.Verdict, rep.ChainPlusAnchor.Reason)
	}
	if rep.Verdict != vREFUSE {
		t.Errorf("overall = %s, want REFUSE", rep.Verdict)
	}
}

// A mutated chain is the CHAIN's to detect. The anchor half stays PASS because
// mutation leaves head and count untouched — which is precisely why the two are
// reported separately.
func TestAnchorVerify_MutationIsTheChainHalf(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")

	healthy(t, cp, 7)
	mustAnchor(t, cp, ap)
	reorder(t, cp, 2) // changes record content, not the count

	rep, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	if rep.ChainAlone.Verdict != vDETECTED {
		t.Fatalf("chain_alone = %s on a reordered chain, want DETECTED", rep.ChainAlone.Verdict)
	}
	if rep.Verdict != vDETECTED {
		t.Errorf("overall = %s, want DETECTED", rep.Verdict)
	}
}

// The strength cross-check is opt-in, so a seam that never asked about strength
// is never blocked by it (§11.4.201(1)).
func TestAnchorVerify_StrengthCheckIsOptIn(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "chain.jsonl")
	ap := filepath.Join(dir, "anchor.json")
	healthy(t, cp, 4)
	mustAnchor(t, cp, ap)

	rep, err := cmdAnchorVerify([]string{"--chain", cp, "--anchor", ap})
	if err != nil {
		t.Fatalf("anchor verify: %v", err)
	}
	if rep.AnchorStrength.Verdict != vSKIP {
		t.Errorf("anchor_strength = %s with no --remote, want SKIP", rep.AnchorStrength.Verdict)
	}
	if rep.Verdict != vPASS {
		t.Errorf("overall = %s: an opt-in check must not block a seam that never opted in", rep.Verdict)
	}
}

// ---- end to end: the real binary, the real exit code -----------------------

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "continuum-integrity")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, stderr.String())
	}
	return bin
}

// runCLI captures the exit status DIRECTLY from the process, never inferred
// from output.
func runCLI(t *testing.T, bin string, args ...string) (stdout string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	switch e := err.(type) {
	case nil:
		code = 0
	case *exec.ExitError:
		code = e.ExitCode()
	default:
		t.Fatalf("running %v: %v", args, err)
	}
	return out.String(), code
}

func decodeReport(t *testing.T, s string) report {
	t.Helper()
	var rep report
	if err := json.Unmarshal([]byte(s), &rep); err != nil {
		t.Fatalf("stdout is not a JSON report: %v\n%s", err, s)
	}
	return rep
}

func TestEndToEnd_ExitCodesAndJSON(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()

	healthyPath := filepath.Join(dir, "healthy.jsonl")
	healthy(t, healthyPath, 8)

	tamperedPath := filepath.Join(dir, "tampered.jsonl")
	healthy(t, tamperedPath, 8)
	reorder(t, tamperedPath, 3)

	absentPath := filepath.Join(dir, "absent.jsonl")

	// A lagging anchor over a chain that grew: the negative control.
	lagChain := filepath.Join(dir, "lag.jsonl")
	lagAnchor := filepath.Join(dir, "lag.anchor.json")
	healthy(t, lagChain, 5)
	if _, code := runCLI(t, bin, "anchor", "write", "--chain", lagChain, "--anchor", lagAnchor); code != exitPASS {
		t.Fatalf("seeding the lagging anchor exited %d, want %d", code, exitPASS)
	}
	healthy(t, lagChain, 9)

	// A truncated chain under a standing anchor.
	truncChain := filepath.Join(dir, "trunc.jsonl")
	truncAnchor := filepath.Join(dir, "trunc.anchor.json")
	healthy(t, truncChain, 9)
	if _, code := runCLI(t, bin, "anchor", "write", "--chain", truncChain, "--anchor", truncAnchor); code != exitPASS {
		t.Fatalf("seeding the truncation anchor exited %d, want %d", code, exitPASS)
	}
	truncateRecords(t, truncChain, 4)

	for _, c := range []struct {
		name     string
		args     []string
		wantCode int
		wantTop  string
		wantCA   string
		wantCPA  string
	}{
		{"healthy chain verify", []string{"chain", "verify", "--chain", healthyPath}, exitPASS, vPASS, vPASS, vSKIP},
		{"tampered chain verify", []string{"chain", "verify", "--chain", tamperedPath}, exitDETECTED, vDETECTED, vDETECTED, vSKIP},
		{"absent chain verify", []string{"chain", "verify", "--chain", absentPath}, exitREFUSE, vREFUSE, vREFUSE, vSKIP},
		{"lagging anchor verify", []string{"anchor", "verify", "--chain", lagChain, "--anchor", lagAnchor}, exitPASS, vPASS, vPASS, vPASS},
		{"truncated anchor verify", []string{"anchor", "verify", "--chain", truncChain, "--anchor", truncAnchor}, exitDETECTED, vDETECTED, vPASS, vDETECTED},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, code := runCLI(t, bin, c.args...)
			if code != c.wantCode {
				t.Errorf("exit = %d, want %d\n%s", code, c.wantCode, out)
			}
			rep := decodeReport(t, out)
			if rep.Verdict != c.wantTop {
				t.Errorf("verdict = %s, want %s", rep.Verdict, c.wantTop)
			}
			if rep.ChainAlone.Verdict != c.wantCA {
				t.Errorf("chain_alone = %s, want %s", rep.ChainAlone.Verdict, c.wantCA)
			}
			if rep.ChainPlusAnchor.Verdict != c.wantCPA {
				t.Errorf("chain_plus_anchor = %s, want %s", rep.ChainPlusAnchor.Verdict, c.wantCPA)
			}
			if rep.ExitCode != code {
				t.Errorf("exit_code field = %d but the process exited %d", rep.ExitCode, code)
			}
		})
	}

	t.Run("unknown command is a usage error", func(t *testing.T) {
		if _, code := runCLI(t, bin, "chain", "frobnicate"); code != exitUsage {
			t.Errorf("exit = %d, want %d", code, exitUsage)
		}
	})
	t.Run("missing path fails closed", func(t *testing.T) {
		if _, code := runCLI(t, bin, "chain", "verify"); code != exitError {
			t.Errorf("exit = %d, want %d", code, exitError)
		}
	})
}
