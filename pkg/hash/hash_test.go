package hash

import "testing"

func TestSumStableAndDistinct(t *testing.T) {
	a := Sum([]byte("hello"))
	if a != Sum([]byte("hello")) {
		t.Fatal("Sum not stable")
	}
	if a == Sum([]byte("hellp")) {
		t.Fatal("Sum collided on distinct input")
	}
	if len(a) != 64 {
		t.Fatalf("want 64 hex chars, got %d", len(a))
	}
}

func TestValid(t *testing.T) {
	if !Valid(Sum([]byte("x"))) {
		t.Fatal("real id rejected")
	}
	for _, bad := range []string{"", "zz", Sum([]byte("x")) + "0", repeatStr("g", 64)} {
		if Valid(bad) {
			t.Fatalf("bad id accepted: %q", bad)
		}
	}
}

func TestShort(t *testing.T) {
	id := Sum([]byte("x"))
	if Short(id, 8) != id[:8] {
		t.Fatal("short prefix wrong")
	}
	if Short(id, 999) != id {
		t.Fatal("over-length short must return full id")
	}
}

func repeatStr(c string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += c
	}
	return out
}
