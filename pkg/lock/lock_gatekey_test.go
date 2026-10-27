package lock

import (
	"os"
	"path/filepath"
	"testing"
)

// C4: equivalent spellings of one path share one gate.
func TestGate_KeyNormalised(t *testing.T) {
	d := t.TempDir()
	a := filepath.Join(d, "k.lock")
	b := d + "/sub/../k.lock" // not pre-cleaned by filepath.Join
	if gateFor(a) != gateFor(b) {
		t.Fatal("equivalent paths got different gates")
	}
}

// N2 killer: a relative spelling and its absolute spelling must share a gate
// (key must be Abs+Clean, not Clean alone).
func TestGate_RelativeAndAbsoluteShareGate(t *testing.T) {
	d := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if gateFor("k.lock") != gateFor(filepath.Join(d, "k.lock")) {
		t.Fatal("relative and absolute spellings got different gates")
	}
}
