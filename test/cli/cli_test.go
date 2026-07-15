// Package cli_test drives the REAL shipped continuum binary via os/exec — no
// library shim, no mock (§11.4.27: e2e exercises the real system). It builds the
// executable once, then walks a full operator journey (set -> snapshot -> verify
// -> selfcheck -> resume) exactly as a fresh session / the ruler would.
package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary compiles cmd/continuum into a temp path and returns it.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "continuum")
	// module root is two levels up from test/cli.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/continuum")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\n%s", err, out)
	}
	return bin
}

func TestCLIFullJourney(t *testing.T) {
	bin := buildBinary(t)
	storeDir := t.TempDir()

	run := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "CONTINUUM_STORE="+storeDir, "CONTINUUM_ACTOR=cli-test")
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	mustRun := func(stdin string, args ...string) string {
		out, err := run(stdin, args...)
		if err != nil {
			t.Fatalf("continuum %v: %v\n%s", args, err, out)
		}
		return out
	}

	// resume of an empty store must be graceful, not an error.
	if out := mustRun("", "resume", "--short"); !strings.Contains(out, "no committed streams") {
		t.Fatalf("empty resume: %q", out)
	}

	mustRun("", "set", "--id", "T1/main", "--kind", "main", "--phase", "release",
		"--next", "flash D4", "--goal", "1.2.1 tag", "--owner", "conductor")
	mustRun("", "set", "--id", "T4/x", "--kind", "track", "--next", "await op",
		"--owner", "w4", "--blocker", "operator STOP")
	// JSON stdin path (an agent state).
	mustRun(`{"stream_id":"agent:ruler","kind":"agent","next_action":"rebind","owner":"ruler"}`, "set", "--json")

	snapOut := strings.TrimSpace(mustRun("", "snapshot", "cli journey"))
	if len(snapOut) != 64 {
		t.Fatalf("snapshot id not a 64-hex sha256: %q", snapOut)
	}
	if head := strings.TrimSpace(mustRun("", "head")); head != snapOut {
		t.Fatalf("head %q != snapshot %q", head, snapOut)
	}

	if out := mustRun("", "verify"); !strings.HasPrefix(out, "PASS:") {
		t.Fatalf("verify not PASS: %q", out)
	}
	if out := mustRun("", "selfcheck"); !strings.Contains(out, "good=PASS bad=FAIL negctrl=PASS") {
		t.Fatalf("oracle not intact: %q", out)
	}

	// FRESH-SESSION resume: blocked stream surfaces first, all streams present.
	short := mustRun("", "resume", "--short")
	if !strings.Contains(short, "[1 blocked]") || !strings.Contains(short, "T4/x") {
		t.Fatalf("resume --short did not surface the blocker first: %q", short)
	}
	full := mustRun("", "resume", "--metric")
	for _, want := range []string{"T1/main", "T4/x", "agent:ruler", `"blobs_read":4`} {
		if !strings.Contains(full, want) {
			t.Fatalf("resume --metric missing %q in:\n%s", want, full)
		}
	}
}

// TestCLIFailClosedNoStore proves config fails CLOSED with an actionable message
// (§11.4.6/§11.4.201) rather than guessing a store path when none is configured.
func TestCLIFailClosedNoStore(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "head")
	// scrub any inherited CONTINUUM_STORE and give no --store.
	env := []string{}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "CONTINUUM_STORE=") {
			env = append(env, e)
		}
	}
	cmd.Env = env
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected fail-closed error with no store configured, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "CONTINUUM_STORE") {
		t.Fatalf("fail-closed message must name CONTINUUM_STORE (actionable): %q", out)
	}
}
