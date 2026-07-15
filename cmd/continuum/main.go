// Command continuum is the CLI for the instant-resume continuation engine.
//
// Verbs:
//
//	set        a stream writes/updates its own state (JSON on stdin or flags)
//	snapshot   atomically capture ALL streams into a new Merkle manifest
//	resume     render the compact resume bundle (SHORT + FULL) + cost metric
//	restore    print a stream's (or all streams') committed state as JSON
//	verify     deterministic integrity + round-trip check of HEAD (PASS/FAIL/SKIP)
//	selfcheck  run the golden-good/golden-bad/negative-control oracle
//	diff       O(changed) delta between two snapshots
//	log        the append-only event ledger
//	head       print the current committed snapshot id
//
// The store root comes from --store or $CONTINUUM_STORE; the engine fails
// closed if neither is set (§11.4.6 — never guess a project path).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vasic-digital/continuum/pkg/config"
	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/resume"
	"github.com/vasic-digital/continuum/pkg/snapshot"
	"github.com/vasic-digital/continuum/pkg/store"
	"github.com/vasic-digital/continuum/pkg/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "set":
		err = cmdSet(args)
	case "snapshot":
		err = cmdSnapshot(args)
	case "resume":
		err = cmdResume(args)
	case "restore":
		err = cmdRestore(args)
	case "verify":
		err = cmdVerify(args)
	case "selfcheck":
		err = cmdSelfCheck(args)
	case "diff":
		err = cmdDiff(args)
	case "log":
		err = cmdLog(args)
	case "head":
		err = cmdHead(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "continuum: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "continuum: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `continuum — instant-resume continuation engine

usage: continuum <command> [flags]
  set       write/update one stream's state (JSON on stdin, or flags)
  snapshot  atomically capture ALL streams into a new Merkle manifest
  resume    render the compact resume bundle + cost metric
  restore   print committed stream state(s) as JSON
  verify    integrity + determinism check of HEAD (PASS/FAIL/SKIP)
  selfcheck run the self-validating oracle (golden good/bad/neg-control)
  diff      O(changed) delta between two snapshots
  log       the append-only event ledger
  head      print the current committed snapshot id

store root: --store <path> or $CONTINUUM_STORE (required)
`)
}

// engineFor resolves config + opens the store + builds the engine.
func engineFor(root string) (*snapshot.Engine, config.Config, error) {
	cfg, err := config.Resolve(root)
	if err != nil {
		return nil, cfg, err
	}
	s, err := store.Open(cfg.Root)
	if err != nil {
		return nil, cfg, err
	}
	e := snapshot.New(s, cfg.Actor, cfg.LockTTL)
	e.Evidence = os.Stderr
	return e, cfg, nil
}

// ---- multi-flag helper for repeated string flags ---------------------------

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func cmdSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	root := fs.String("store", "", "store root (or $CONTINUUM_STORE)")
	jsonIn := fs.Bool("json", false, "read a StreamState JSON object from stdin")
	id := fs.String("id", "", "stream id")
	kind := fs.String("kind", "", "stream kind (opaque)")
	phase := fs.String("phase", "", "phase")
	next := fs.String("next", "", "next action")
	goal := fs.String("goal", "", "terminal goal")
	head := fs.String("head", "", "committed-state anchor (git HEAD, checksum...)")
	owner := fs.String("owner", "", "single-writer owner (§11.4.206)")
	var fields, evidence, blockers, constraints multiFlag
	fs.Var(&fields, "field", "extra field k=v (repeatable)")
	fs.Var(&evidence, "evidence", "captured-evidence path (repeatable)")
	fs.Var(&blockers, "blocker", "blocking reason (repeatable)")
	fs.Var(&constraints, "constraint", "binding constraint (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}

	var st model.StreamState
	if *jsonIn {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &st); err != nil {
			return fmt.Errorf("parsing stdin StreamState JSON: %w", err)
		}
	} else {
		if *id == "" {
			return fmt.Errorf("--id required (or use --json to read from stdin)")
		}
		st = model.StreamState{
			StreamID: *id, Kind: *kind, Phase: *phase, NextAction: *next,
			Goal: *goal, Head: *head, Owner: *owner,
			Evidence: evidence, Blockers: blockers, Constraints: constraints,
		}
		if len(fields) > 0 {
			st.Fields = map[string]string{}
			for _, kv := range fields {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("--field %q must be k=v", kv)
				}
				st.Fields[k] = v
			}
		}
	}
	if err := e.Set(st); err != nil {
		return err
	}
	fmt.Printf("set stream %q\n", st.StreamID)
	return nil
}

func cmdSnapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	note := fs.String("note", "", "commit note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	id, err := e.Commit(*note)
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}

func cmdResume(args []string) error {
	fs := flag.NewFlagSet("resume", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	snapID := fs.String("snapshot", "", "snapshot id (default HEAD)")
	short := fs.Bool("short", false, "print only the one-line SHORT bundle")
	max := fs.Int("max", 0, "max streams in FULL (0=all; blocked never dropped)")
	metric := fs.Bool("metric", false, "print the resume-cost metric JSON to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	b, err := resume.Render(e, *snapID, resume.Options{MaxStreams: *max})
	if err != nil {
		return err
	}
	if *short {
		fmt.Println(b.Short)
	} else {
		fmt.Print(b.Full)
	}
	if *metric {
		mj, _ := json.Marshal(b.Metric)
		fmt.Fprintln(os.Stderr, string(mj))
	}
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	snapID := fs.String("snapshot", "", "snapshot id (default HEAD)")
	streamID := fs.String("stream", "", "single stream id (default: all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	if *streamID != "" {
		st, err := e.RestoreStream(*snapID, *streamID)
		if err != nil {
			return err
		}
		return printJSON(st)
	}
	all, _, err := e.RestoreAll(*snapID)
	if err != nil {
		return err
	}
	return printJSON(all)
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	r := verify.Verify(e)
	fmt.Printf("%s: %s\n", r.Verdict, r.Detail)
	if r.Verdict == verify.FAIL {
		os.Exit(1)
	}
	return nil
}

func cmdSelfCheck(args []string) error {
	fs := flag.NewFlagSet("selfcheck", flag.ContinueOnError)
	work := fs.String("work", "", "hermetic work dir (default: a tempdir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *work
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("", "continuum-selfcheck-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
	}
	r, err := verify.SelfCheck(dir)
	if err != nil {
		return err
	}
	fmt.Printf("good=%s bad=%s negctrl=%s\n", r.Good.Verdict, r.Bad.Verdict, r.NegControl.Verdict)
	fmt.Printf("%s: %s\n", r.Overall, r.Detail)
	if r.Overall != verify.PASS {
		os.Exit(1)
	}
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	a := fs.String("a", "", "snapshot A id (empty = empty snapshot)")
	b := fs.String("b", "", "snapshot B id (empty = empty snapshot)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	d, err := e.Diff(*a, *b)
	if err != nil {
		return err
	}
	return printJSON(d)
}

func cmdLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	limit := fs.Int("limit", 0, "show only the last N events (0=all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	evs, err := e.Store.Events()
	if err != nil {
		return err
	}
	if *limit > 0 && len(evs) > *limit {
		evs = evs[len(evs)-*limit:]
	}
	for _, ev := range evs {
		mj, _ := json.Marshal(ev)
		fmt.Println(string(mj))
	}
	return nil
}

func cmdHead(args []string) error {
	fs := flag.NewFlagSet("head", flag.ContinueOnError)
	root := fs.String("store", "", "store root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, _, err := engineFor(*root)
	if err != nil {
		return err
	}
	h, err := e.Head()
	if err != nil {
		return err
	}
	if h == "" {
		fmt.Println("(no committed snapshot)")
		return nil
	}
	fmt.Println(h)
	return nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
