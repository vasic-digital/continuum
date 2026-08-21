// Healthy-chain construction (T319 support).
//
// This builds a chain that is genuinely valid — not one that merely looks valid
// to the verifier that is about to read it. Every record is serialised with the
// SAME canonicaliser (model.Canonical) and linked with the SAME digest
// (chain.Digest) that pkg/chain's decoder and walk use, so a healthy chain built
// here and a healthy chain produced anywhere else are byte-identical. A private
// encoder here would be a fork whose drift stayed invisible until a digest
// quietly stopped matching (§11.4.251).
//
// Why this lives in the package rather than in a _test.go file: it is the
// FALSE-POSITIVE GUARD's fixture. A verifier that refuses everything satisfies
// every refusal assertion and is useless, so the negative control — a healthy
// chain that MUST still PASS — is load-bearing (§11.4.201(1)). Keeping the
// builder in the package means the unit test's negative control and any gate's
// negative control are produced by one implementation, so they cannot drift
// apart and quietly stop testing the same thing.
package verify

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vasic-digital/continuum/pkg/chain"
	"github.com/vasic-digital/continuum/pkg/model"
)

// healthyChainBase is a fixed instant. Fixture bytes must be deterministic:
// reading the wall clock would make two runs of the same builder produce
// different digests, and a fixture that changes under you cannot be a contract.
var healthyChainBase = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// WriteHealthyChainForTest writes a valid n-record chain in JSONL form to path.
//
// The chain is real: record 0 carries chain.GenesisPrev, and every later record
// carries the digest of its actual predecessor, so pkg/chain's walk verifies it
// PASS for the honest reason rather than by construction of a special case.
//
// n == 0 writes an empty file. That is a legitimate chain (pkg/chain treats an
// empty chain as vacuously consistent, with wholesale deletion left to the
// anchor's entry_count), so it is permitted rather than rejected here.
func WriteHealthyChainForTest(path string, n int) error {
	if n < 0 {
		return fmt.Errorf("continuum/verify: WriteHealthyChainForTest: n=%d is negative", n)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("continuum/verify: preparing %q: %w", dir, err)
		}
	}

	var buf bytes.Buffer
	prev := chain.GenesisPrev

	for i := 0; i < n; i++ {
		r := chain.Record{
			Seq: int64(i + 1),
			Ts:  healthyChainBase.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			// A plausible recorded call rather than filler: a chain of empty
			// commands would still link correctly and would prove less.
			Command:      fmt.Sprintf("run-gate --case %d", i),
			ExitStatus:   0,
			ArtifactPath: fmt.Sprintf("qa-results/002-anti-slop/chain/healthy_%02d.log", i),
			// Values match the fixture corpus generator's conventions so a
			// healthy chain built here is shaped like a real one.
			EvidenceClass:    "runtime",
			AuthorSessionID:  "verify-healthy-builder",
			IndependenceTier: "instance",
			PrevDigest:       prev,
		}

		// The line bytes ARE the canonical bytes: same encoder the digest is
		// taken over, so what is written is exactly what the decoder expects.
		line, err := model.Canonical(r)
		if err != nil {
			return fmt.Errorf("continuum/verify: canonicalising record %d: %w", i, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')

		// Link the NEXT record to this one's real content digest.
		d, err := chain.Digest(r)
		if err != nil {
			return fmt.Errorf("continuum/verify: digesting record %d: %w", i, err)
		}
		prev = d
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("continuum/verify: writing %q: %w", path, err)
	}
	return nil
}
