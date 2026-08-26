// continuum-unionrule — verifies an evidence chain against the union rule for
// the commands an execution recorder actually recorded (FR-026/FR-027/FR-028).
//
// # What this answers
//
//	Does the chain hold at least one entry for every command that ran?
//
// The execution recorder (FR-045) writes one row per command it EXECUTED. Every
// such row is a state-changing call, so the union rule requires an entry for
// each. This tool classifies the recorder's rows through the shipped
// classifier and checks the chain against that demand.
//
// # Why this exists as a program and not as another test
//
// A classifier called only from its own unit tests classifies nothing that
// happens (§11.4.108: source-present is not runtime-active). This is the
// consumer that makes the rule bind on real recorded work. It is also the only
// non-test caller of the union-rule API, which is what CM-CHAIN-ENTRY-UNION-RULE
// UNION-A6/A7 assert -- so if this program stops calling the classifier, that
// gate FAILs rather than the wiring rotting unnoticed.
//
// # Honest boundary (§11.4.6)
//
// This is a COUNT check, inherited unchanged from chain.VerifyComplete: Call
// carries no identity, so a chain holding the right NUMBER of entries for the
// WRONG commands passes here. It catches a recorder that ran commands nothing
// recorded; it does not correlate row to record. Closing that needs a
// correlation key on both sides -- a change to the recording path, not
// something this program can infer from the data it is handed.
//
// Usage:
//
//	continuum-unionrule --recorder <exec-record.jsonl> --chain <chain.jsonl>
//
// Exit status:
//
//	0  PASS      the chain satisfies the union rule's demand
//	1  DETECTED/REFUSE   it does not, or the chain could not be walked
//	2  the inputs could not be read or classified (fails closed, never a pass)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vasic-digital/continuum/pkg/chain"
)

func main() {
	recorder := flag.String("recorder", "", "FR-045 execution recorder JSONL")
	chainPath := flag.String("chain", "", "E2 evidence chain JSONL")
	flag.Parse()

	if *recorder == "" || *chainPath == "" {
		fmt.Fprintln(os.Stderr, "usage: continuum-unionrule --recorder <f> --chain <f>")
		os.Exit(2)
	}

	rowBytes, err := os.ReadFile(*recorder)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading recorder %q: %v\n", *recorder, err)
		os.Exit(2)
	}
	chainBytes, err := os.ReadFile(*chainPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading chain %q: %v\n", *chainPath, err)
		os.Exit(2)
	}

	rows, err := chain.DecodeExecRows(rowBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recorder: %v\n", err)
		os.Exit(2)
	}
	recs, err := chain.Decode(chainBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain: %v\n", err)
		os.Exit(2)
	}

	rep, calls, err := chain.VerifyExecRows(recs, rows)
	if err != nil {
		// A row that could not be classified is refused, never waved through.
		fmt.Fprintf(os.Stderr, "classify: %v\n", err)
		os.Exit(2)
	}

	// Show the working. Each of these numbers comes from the shipped
	// classifier, so a broken classifier changes what this program reports --
	// which is what makes the wiring load-bearing rather than decorative.
	stateChanging := 0
	requiring := 0
	for _, c := range calls {
		if chain.IsStateChanging(c.Kind) {
			stateChanging++
		}
		if chain.RequiresEntry(c) {
			requiring++
		}
	}
	required := chain.RequiredEntries(calls)

	fmt.Printf("UNIONRULE calls=%d state_changing=%d requiring_entry=%d required=%d entries=%d\n",
		len(calls), stateChanging, requiring, required, len(recs))
	fmt.Printf("UNIONRULE verdict=%s\n", rep.Verdict)
	for _, f := range rep.Findings {
		fmt.Printf("UNIONRULE finding kind=%s seq=%d detail=%s\n", f.Kind, f.Seq, f.Detail)
	}

	if rep.Verdict != chain.PASS {
		os.Exit(1)
	}
}
