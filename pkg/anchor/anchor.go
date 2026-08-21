// Package anchor holds the EXTERNAL record of what an evidence chain should be,
// and the check that compares a chain against it.
//
// # Why this package exists at all (research D-2, measured)
//
// A hash chain proves INTERNAL consistency and nothing else. On a purpose-built
// 100,000-entry ledger attacked four ways, mutation, deletion and reorder were
// detected by the chain — but tail truncation was NOT, and deletion followed by
// a full re-chain was NOT: an adversary recomputed the entire 100k chain in
// 0.43 s and chain-alone verification reported PASS. Both of those attacks leave
// behind a structurally VALID chain, and a chain cannot know what it *should*
// have contained.
//
// Only an external record of the expected head and entry count carries that.
// Hence, stated plainly: THE SECURITY LIVES IN THE ANCHOR, and the window of
// forgeability equals the anchor interval. Against a same-user adversary a hash
// chain alone is security theatre; its real value is detecting accidental
// corruption, holding a total order that cannot drift silently, and making
// tampering require deliberate reconstructive effort.
//
// # This package imports NOTHING from pkg/chain
//
// The dependency runs one way. The chain hands this package a ChainSummary —
// head digest, count, and an accessor for the digest of any prefix — and this
// package decides. That keeps the anchor comparison usable by a verifier that
// walks a chain, by one that reads a store, and by a shell seam, without any of
// them forking a second copy of the rule (§11.4.251).
//
// # Honest boundary (§11.4.6)
//
// An anchor detects that a chain is not the chain that was anchored. It does
// NOT make any record TRUE: a false record, honestly chained and honestly
// anchored, verifies perfectly. It also cannot detect an entry that was never
// written. Neither limit is a defect to be fixed here; both are stated so no
// reader mistakes this mechanism for more than it is.
package anchor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/model"
)

// Anchor is the external record of what the chain should be.
//
// Field declaration order is the canonical byte order (model.Canonical emits
// struct fields in declaration order), so this order is part of the on-disk
// contract and MUST match the fixture corpus in test/fixtures/chain.
type Anchor struct {
	// HeadDigest is the digest of the last record that was anchored.
	HeadDigest string `json:"head_digest"`

	// EntryCount is how many entries the chain held when this anchor was
	// taken. It is NOT optional, and the reason is specific: head_digest alone
	// makes WHOLESALE DELETION silent. Delete the entire store and there is no
	// head to compare — an absence with nothing to measure it against reads as
	// "nothing to check" rather than "everything is gone". The count is what
	// turns that silence into a DETECTED ABSENCE (FR-037).
	EntryCount int `json:"entry_count"`

	// Strength is drawn from the closed set below and is PROBED, never assumed
	// (FR-038). See strength.go: policy-forbidden is not mechanically-prevented,
	// and recording "mechanism" without a probe result is the exact theatre this
	// feature exists to prevent.
	Strength string `json:"anchor_strength"`
}

// Strength values (closed set).
//
// StrengthUnknown is the third, usually-missed outcome: a remote that could not
// be probed tells us nothing, and nothing is what must be recorded. Collapsing
// it into StrengthPolicy would convert an UNKNOWN into a claim (§11.4.6).
const (
	StrengthPolicy    = "policy"
	StrengthMechanism = "mechanism"
	StrengthUnknown   = "unknown"
)

// Validation errors, exported so a caller can branch on the reason rather than
// string-matching a message.
var (
	ErrNoHeadDigest     = errors.New("anchor: head_digest is absent or malformed")
	ErrNoEntryCount     = errors.New("anchor: entry_count is absent (an anchor without a count cannot detect wholesale deletion)")
	ErrUnknownStrength  = errors.New("anchor: anchor_strength is not one of policy|mechanism|unknown")
	ErrAnchorRegression = errors.New("anchor: refusing to move an anchor backwards")
	ErrAnchorRewrite    = errors.New("anchor: refusing to rewrite an already-anchored state")
)

// Validate reports whether a is a usable anchor.
//
// It enforces the FR-037 completeness fields. The FR-038 honesty of the
// strength VALUE is enforced separately by ValidateRecordedStrength, which is
// the only check that can see the probe result; all Validate can do here is
// refuse a value outside the closed set.
func Validate(a Anchor) error {
	if !hash.Valid(a.HeadDigest) {
		return fmt.Errorf("%w (got %q)", ErrNoHeadDigest, a.HeadDigest)
	}
	// Zero is refused deliberately, and it is not pedantry. An adversary who
	// deletes the store and presents a count of 0 would otherwise hand over an
	// internally "consistent" pair that verifies clean. You do not anchor an
	// empty chain, so 0 is absence, not a legitimate value.
	if a.EntryCount <= 0 {
		return fmt.Errorf("%w (got %d)", ErrNoEntryCount, a.EntryCount)
	}
	switch a.Strength {
	case StrengthPolicy, StrengthMechanism, StrengthUnknown, "":
		// "" is treated as unknown-not-yet-recorded rather than refused here,
		// so an honest SKIP from an unprobeable remote remains writable. The
		// overstatement this guards against — recording `mechanism` with no
		// probe behind it — is caught by ValidateRecordedStrength.
	default:
		return fmt.Errorf("%w (got %q)", ErrUnknownStrength, a.Strength)
	}
	return nil
}

// Read loads an anchor from path. A malformed anchor file is an ERROR, never a
// zero-valued Anchor: silently returning an empty struct would make an
// unreadable anchor indistinguishable from one recording an empty chain.
func Read(path string) (Anchor, error) {
	var a Anchor
	b, err := os.ReadFile(path)
	if err != nil {
		return a, fmt.Errorf("anchor: reading %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, fmt.Errorf("anchor: %s is not an anchor record: %w", path, err)
	}
	return a, nil
}

// Write records a at path, atomically and forward-only.
//
// Forward-only is this package's local expression of the absolute no-force-push
// rule (§11.4.113). An anchor is only worth anything if the producer can APPEND
// to it but not REWRITE it, so:
//
//   - a lower entry_count than the anchor already on disk is REFUSED (that is
//     the anchor being dragged backwards to match a truncated chain);
//   - the same entry_count with a different head_digest is REFUSED (that is the
//     anchored state itself being rewritten);
//   - the identical anchor is a no-op, so re-running the writer is safe.
//
// Honest boundary (§11.4.6): this writes the anchor FILE. Publishing it to the
// multi-remote push target is the shell seam's job (T315/T323) and is NOT done
// here — this function must not be read as evidence that a push happened.
func Write(path string, a Anchor) error {
	if err := Validate(a); err != nil {
		return err
	}
	if prev, err := Read(path); err == nil {
		if err := checkForward(prev, a); err != nil {
			return err
		}
		if prev == a {
			return nil // idempotent: identical anchor already recorded
		}
	} else if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(errors.Unwrap(err)) {
		// A path that exists but cannot be parsed is refused rather than
		// overwritten: overwriting it would destroy the only evidence that
		// something already went wrong there.
		return fmt.Errorf("anchor: refusing to overwrite an unreadable anchor at %s: %w", path, err)
	}

	b, err := model.Canonical(a)
	if err != nil {
		return fmt.Errorf("anchor: canonicalising: %w", err)
	}
	return writeFileAtomic(path, append(b, '\n'))
}

// checkForward is the forward-only rule, factored out so Write reads as policy
// and the rule itself stays testable in isolation.
func checkForward(prev, next Anchor) error {
	if next.EntryCount < prev.EntryCount {
		return fmt.Errorf("%w: on disk entry_count=%d, offered %d",
			ErrAnchorRegression, prev.EntryCount, next.EntryCount)
	}
	if next.EntryCount == prev.EntryCount && next.HeadDigest != prev.HeadDigest {
		return fmt.Errorf("%w: entry_count=%d already anchored at head %s, offered %s",
			ErrAnchorRewrite, prev.EntryCount,
			hash.Short(prev.HeadDigest, 12), hash.Short(next.HeadDigest, 12))
	}
	return nil
}

// writeFileAtomic writes b to path via temp-in-the-same-directory, fsync,
// rename, and an fsync of the DIRECTORY (§11.4.205(6)).
//
// The directory fsync is the step that is usually dropped: rename(2) is atomic
// for a concurrent reader but is NOT durable without it, so a crash can leave
// the anchor absent even though the write "succeeded". A temp file in /tmp
// would also break atomicity, because a cross-filesystem rename degrades to a
// copy, and a copy can tear.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("anchor: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".anchor-*.tmp")
	if err != nil {
		return fmt.Errorf("anchor: creating temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("anchor: writing temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("anchor: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("anchor: closing temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("anchor: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("anchor: rename into place: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("anchor: opening %s to fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("anchor: fsync %s: %w", dir, err)
	}
	return nil
}
