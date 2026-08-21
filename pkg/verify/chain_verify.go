// Chain-walk verification (T319 — FR-009, FR-029, FR-030).
//
// This file extends the package's existing snapshot verifier with the evidence
// CHAIN verifier. The two share one vocabulary on purpose: a seam that reads a
// Result should not have to know which verifier produced it.
//
// # The vocabulary this file adds
//
//	PASS | FAIL | SKIP   ->   PASS | FAIL | SKIP | DETECTED | REFUSE
//
// REFUSE is the load-bearing addition. A verifier that hits an unreadable
// store, a half-written record or a malformed line and returns "no findings"
// is indistinguishable, at the seam, from a verifier that walked everything and
// found nothing wrong. Zero findings then means either "clean" or "blind", and
// the reader cannot tell which (§11.4.201(6): a null is not evidence until the
// instrument is proven able to see).
//
// So REFUSE, SKIP and PASS are three different states and are never merged:
//
//	PASS   — the walk completed and every link held.
//	DETECTED — the walk completed and found a named alteration.
//	REFUSE — this applies here and the walk could not decide. Blocking.
//	SKIP   — this does not apply here. Honest, non-blocking.
//
// # No second chain implementation
//
// Every chain concern — the canonical byte order, the digest, the decode rules
// and the link walk — belongs to pkg/chain and is CALLED here, never restated
// (§11.4.251). This file is the file-and-verdict boundary around that walk: it
// turns "I could not read the bytes" into a refusal, and it translates a
// chain.Report into this package's Result. If you find yourself re-deriving a
// prev_digest here, stop: that is the fork this note exists to prevent.
//
// # Honest boundary: what a chain-alone PASS does and does not mean
//
// A chain-alone PASS means the records PRESENT are internally consistent. It
// does NOT mean the chain is COMPLETE. Two attacks pass here by design and are
// caught one layer up, by the anchor's head_digest and entry_count (FR-037):
//
//   - tail truncation — whole records removed from the end. What remains is a
//     valid chain, so it PASSes here. It is caught by comparing the walked head
//     and count against the anchor.
//   - deletion + full re-chain — records removed and every successor re-digested.
//     Also internally valid, also caught only against the anchor.
//
// That boundary is measured and recorded in pkg/chain's attack matrix. It is
// stated here so a reader of this file cannot mistake PASS for "complete".
//
// Note the distinction this file DOES draw, which is easy to lose: a RECORD-level
// tail truncation (whole lines gone) decodes cleanly and PASSes, while a BYTE-level
// truncation (a final line cut mid-write) is malformed and REFUSES. Collapsing the
// two would either refuse every legitimately-shortened chain or silently accept a
// half-written one, so the split is deliberate.
//
// An empty-but-present chain file also PASSes, for the reason pkg/chain records
// at its own empty-chain branch: refusing it would false-refuse every
// legitimately-empty chain, and wholesale deletion is the anchor's entry_count
// to catch. A MISSING file is a different thing entirely and refuses — see
// VerifyChainFile.
package verify

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/vasic-digital/continuum/pkg/chain"
)

const (
	// DETECTED — an alteration was found; Detail names it.
	DETECTED Verdict = "DETECTED"
	// REFUSE — verification applied and could not COMPLETE. Never collapsed
	// into PASS (FR-030) and never into SKIP: "could not decide" and "does not
	// apply" are different answers and only one of them blocks.
	REFUSE Verdict = "REFUSE"
)

// maxRenderedFindings bounds how many findings are RENDERED into Detail. The
// reported count is always the true total, so nothing is hidden — only the
// rendering is capped, and the message says so when it truncates.
const maxRenderedFindings = 20

// VerifyChainFile walks the evidence chain at path and returns a verdict.
//
// The walk is COMPLETE, never sampled: full verification of 100k entries was
// measured at 0.21 s, so there is no budget argument for checking a subset, and
// a sampled walk could only report "the parts I looked at were fine".
//
// Refusals, each naming its reason:
//
//   - the file is absent — the walk never started. "There is nothing here" must
//     never read as "nothing is wrong"; that is the wholesale-deletion case.
//   - the file cannot be read — the instrument is blind, so its zero findings
//     say nothing about the content.
//   - the bytes cannot be decoded — a malformed or half-written record stops the
//     walk, leaving every record beyond it unverified. pkg/chain refuses to skip
//     such a line precisely so the hole cannot close over silently.
//   - pkg/chain itself refused, or returned a verdict this mapping does not
//     recognise — see the default branch below.
func VerifyChainFile(path string) Result {
	b, err := os.ReadFile(path)
	if err != nil {
		return Result{REFUSE, readRefusalReason(path, err)}
	}

	recs, err := chain.Decode(b)
	if err != nil {
		what := "could not be decoded"
		if errors.Is(err, chain.ErrMalformedRecord) {
			what = "carries a record that is not exactly one canonical record"
		}
		return Result{REFUSE, fmt.Sprintf(
			"chain store %q %s: %v — the walk stopped there, so every record beyond it is UNVERIFIED; "+
				"this is an undecided result, not a clean one",
			path, what, err)}
	}

	return fromChainReport(path, len(recs), chain.Verify(recs))
}

// readRefusalReason classifies a read failure from the error itself, never from
// its message text (§11.4.6: the class is determined, not guessed).
func readRefusalReason(path string, err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf(
			"chain store %q is ABSENT: the walk never started, so nothing was verified. "+
				"An absent store is the wholesale-deletion case and must never be reported as intact (%v)",
			path, err)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Sprintf(
			"chain store %q could not be read (permission): the instrument is blind here, "+
				"so zero findings would say nothing about the content (%v)",
			path, err)
	default:
		return fmt.Sprintf(
			"chain store %q could not be read: %v — the walk could not start, so this result is "+
				"undecided rather than clean",
			path, err)
	}
}

// fromChainReport translates a chain.Report into this package's Result.
//
// The default branch is deliberate and fail-closed (§11.4.252). If pkg/chain
// ever grows a verdict this mapping has not been taught, the honest answer is
// REFUSE — an unrecognised verdict has decided nothing. Falling through to PASS
// (or to the zero value, which is neither PASS nor a refusal) would let a future
// verdict be silently reported as success, which is the exact failure REFUSE was
// added to prevent.
func fromChainReport(path string, walked int, rep chain.Report) Result {
	switch rep.Verdict {
	case chain.PASS:
		return Result{PASS, fmt.Sprintf(
			"chain %q: %d record(s) walked, every prev_digest link intact (chain-alone; "+
				"completeness is the anchor's head_digest + entry_count to confirm)",
			path, walked)}

	case chain.DETECTED:
		return Result{DETECTED, fmt.Sprintf(
			"chain %q: %d record(s) walked, %d finding(s): %s",
			path, walked, len(rep.Findings), renderFindings(rep.Findings))}

	case chain.REFUSE:
		return Result{REFUSE, fmt.Sprintf(
			"chain %q: the walk could not complete after %d record(s), %d finding(s): %s — "+
				"records beyond that point are UNVERIFIED",
			path, walked, len(rep.Findings), renderFindings(rep.Findings))}

	default:
		return Result{REFUSE, fmt.Sprintf(
			"chain %q: pkg/chain returned verdict %q, which this mapping does not recognise. "+
				"An unrecognised verdict has decided nothing and is refused rather than passed",
			path, rep.Verdict)}
	}
}

// renderFindings formats findings for an operator. A detection nobody can act on
// is barely better than silence, so kind, seq and detail are all carried.
func renderFindings(found []chain.Finding) string {
	if len(found) == 0 {
		// A DETECTED or REFUSE verdict with no findings is itself a defect in
		// the reporting path; say so rather than emitting an empty reason.
		return "(no findings were attached to this verdict — the reason is missing, " +
			"which is itself a reporting defect)"
	}
	shown := found
	suffix := ""
	if len(shown) > maxRenderedFindings {
		shown = shown[:maxRenderedFindings]
		suffix = fmt.Sprintf(" … and %d more (count above is the true total; only this listing is capped)",
			len(found)-maxRenderedFindings)
	}
	parts := make([]string, 0, len(shown))
	for _, f := range shown {
		parts = append(parts, fmt.Sprintf("[%s seq=%d] %s", f.Kind, f.Seq, f.Detail))
	}
	return strings.Join(parts, "; ") + suffix
}
