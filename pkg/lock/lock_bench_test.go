package lock

import (
	"path/filepath"
	"testing"
)

// BenchmarkAcquireRelease measures one uncontended acquire+release cycle. The
// lockfile is not fsynced; run with TMPDIR on a journalled disk to see the cost
// a per-acquire fsync used to add.
func BenchmarkAcquireRelease(b *testing.B) {
	p := filepath.Join(b.TempDir(), "x.lock")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l, err := Acquire(p, Options{})
		if err != nil {
			b.Fatal(err)
		}
		_ = l.Release()
	}
}
