package lock

import (
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
