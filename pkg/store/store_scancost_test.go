package store

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasic-digital/continuum/pkg/model"
)

func appendOne(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.AppendEvent(model.Event{Time: "2026-10-28T10:00:00Z", Type: "set", Stream: "T1/main"}); err != nil {
		t.Fatal(err)
	}
}

// Residual R2: AppendEvent re-read and re-parsed the WHOLE ledger under the
// exclusive lock on every append (O(n) per append, O(n^2) over a run). A handle
// that already verified a prefix must read only the bytes appended since.
func TestAppendEvent_ScanCostIsIncremental(t *testing.T) {
	s, _ := seedLedger(t, 300)
	var per int64
	{
		before := scanBytesRead.Load()
		appendOne(t, s)
		per = scanBytesRead.Load() - before
	}
	st, err := os.Stat(ledgerPath(s.Root))
	if err != nil {
		t.Fatal(err)
	}
	// One append may re-read only the bytes added since the last verification
	// (here: nothing, the same handle wrote the previous record). Allow a few
	// records of slack; the full ledger is hundreds of records.
	recordSize := st.Size() / 301
	if per > 4*recordSize {
		t.Fatalf("append #301 read %d bytes of a %d-byte ledger (record ~%d bytes): scan is not incremental", per, st.Size(), recordSize)
	}
}

// Correctness of the incremental scan: records appended by ANOTHER handle after
// this handle's last verification must be seen, so sequences stay a total order.
func TestAppendEvent_IncrementalScanSeesOtherHandle(t *testing.T) {
	a, root := seedLedger(t, 5)
	b, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		appendOne(t, b)
	}
	ev, err := a.AppendEvent(model.Event{Time: "2026-10-28T10:00:01Z", Type: "set"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Seq != 9 {
		t.Fatalf("handle a assigned seq %d after b appended 3 records, want 9", ev.Seq)
	}
}

// If the ledger is replaced or truncated underneath a handle, the cached prefix
// is void and a full re-verification must run (a stale offset past EOF, or into
// different bytes, must never be trusted).
func TestAppendEvent_IncrementalScanResetsOnTruncation(t *testing.T) {
	s, root := seedLedger(t, 10)
	if err := os.WriteFile(ledgerPath(root), []byte(`{"seq":1,"time":"t","type":"set"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, err := s.AppendEvent(model.Event{Time: "t2", Type: "set"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Seq != 2 {
		t.Fatalf("after the ledger was replaced by a 1-record file, next seq = %d, want 2", ev.Seq)
	}
}

// Garbage appended by another writer AFTER this handle verified its prefix is in
// the newly-read region and must still be refused.
func TestAppendEvent_IncrementalScanStillRefusesNewGarbage(t *testing.T) {
	s, root := seedLedger(t, 5)
	f, err := os.OpenFile(ledgerPath(root), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("this is not json\n")
	f.Close()
	if _, err := s.AppendEvent(model.Event{Time: "t", Type: "set"}); err == nil {
		t.Fatal("garbage line appended after the verified prefix was not refused")
	}
}

// A ledger replaced by a different file (new inode) that is as large as or
// larger than the previously verified prefix must still void the cache: size
// alone cannot tell "same file grew" from "different file".
func TestAppendEvent_IncrementalScanResetsOnReplacedFile(t *testing.T) {
	s, root := seedLedger(t, 3)
	pad := strings.Repeat("x", 4096)
	repl := filepath.Join(root, "replacement.tmp")
	body := ""
	for i := 0; i < 3; i++ {
		body += fmt.Sprintf(`{"seq":1,"time":"t","type":"set","pad":%q}`+"\n", pad)
	}
	if err := os.WriteFile(repl, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(repl, ledgerPath(root)); err != nil {
		t.Fatal(err)
	}
	ev, err := s.AppendEvent(model.Event{Time: "t2", Type: "set"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Seq != 2 {
		t.Fatalf("after the ledger file was replaced, next seq = %d, want 2 (cache from the old inode must not be reused)", ev.Seq)
	}
}

func appendRaw(t *testing.T, root, data string) {
	t.Helper()
	f, err := os.OpenFile(ledgerPath(root), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

// A line that parses but carries no sequence occupies no position in the total
// order; the incremental scan must refuse it exactly as the full scan did.
func TestAppendEvent_IncrementalScanRefusesSeqlessLine(t *testing.T) {
	s, root := seedLedger(t, 2)
	appendRaw(t, root, `{"type":"set","time":"t"}`+"\n")
	_, err := s.AppendEvent(model.Event{Time: "t2", Type: "set"})
	if !errors.Is(err, ErrUnverifiableTail) {
		t.Fatalf("append after a seq-less line: err = %v, want ErrUnverifiableTail", err)
	}
}

// An unterminated (still-being-written) final line is verified but not cached:
// once its writer finishes it, the next scan re-reads it and reports later
// problems at the true line number.
func TestScanLastSeq_UnterminatedTailNotCached_LineNumbersStayTrue(t *testing.T) {
	s, root := seedLedger(t, 2)
	appendRaw(t, root, `{"seq":3,"time":"t","type":"set"}`) // no newline yet
	last, err := s.scanLastSeq()
	if err != nil || last != 3 {
		t.Fatalf("scan over unterminated valid tail: last=%d err=%v, want 3, nil", last, err)
	}
	appendRaw(t, root, "\nnot json at all\n")
	_, err = s.scanLastSeq()
	if !errors.Is(err, ErrUnverifiableTail) || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("err = %v, want ErrUnverifiableTail naming line 4", err)
	}
}

// F2: truncate-and-regrow of the SAME inode past the cached offset. Size and
// identity checks alone trust the stale cache and report the old maximum (10)
// instead of the real one (2), so the next append would be seq 11.
func TestAppendEvent_IncrementalScanResetsOnSameInodeRegrow(t *testing.T) {
	s, root := seedLedger(t, 10)
	st, _ := os.Stat(ledgerPath(root))
	pad := strings.Repeat("x", int(st.Size()))
	f, err := os.OpenFile(ledgerPath(root), os.O_WRONLY|os.O_TRUNC, 0o644) // same inode
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		fmt.Fprintf(f, `{"seq":%d,"time":"%s","type":"set"}`+"\n", i, pad)
	}
	f.Close()
	ev, err := s.AppendEvent(model.Event{Time: "t", Type: "set"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Seq != 3 {
		t.Fatalf("after same-inode rewrite to 2 records, next seq = %d, want 3 (stale cache trusted)", ev.Seq)
	}
}

// F3: the cache must hold the maximum over the TERMINATED prefix only. If an
// unterminated tail carrying a high seq is later removed, that seq must not
// survive in the cache and open a gap.
func TestScanLastSeq_RemovedUnterminatedTailLeavesNoPhantomSeq(t *testing.T) {
	s, root := seedLedger(t, 2)
	appendRaw(t, root, `{"seq":9,"time":"t","type":"set"}`) // unterminated
	if last, err := s.scanLastSeq(); err != nil || last != 9 {
		t.Fatalf("with tail: last=%d err=%v", last, err)
	}
	st, _ := os.Stat(ledgerPath(root))
	tail := int64(len(`{"seq":9,"time":"t","type":"set"}`))
	if err := os.Truncate(ledgerPath(root), st.Size()-tail); err != nil {
		t.Fatal(err)
	}
	last, err := s.scanLastSeq()
	if err != nil || last != 2 {
		t.Fatalf("after tail removed: last=%d err=%v, want 2 (phantom seq cached)", last, err)
	}
}

// F6: an unterminated line of exactly the bound is refused, as the old Scanner
// refused it, and newline-free input is never buffered beyond the bound.
func TestScanLastSeq_UnboundedUnterminatedLineRefused(t *testing.T) {
	s, root := seedLedger(t, 1)
	appendRaw(t, root, strings.Repeat("a", 4*1024*1024))
	if _, err := s.scanLastSeq(); err == nil {
		t.Fatal("4 MiB unterminated line accepted")
	}
	appendRaw(t, root, strings.Repeat("a", 1024))
	if _, err := s.scanLastSeq(); err == nil {
		t.Fatal("over-bound line accepted")
	}
}

// F6 at unit level, unaligned to any chunk size: the bound matches the old
// Scanner (a line of max bytes INCLUDING its newline is fine; one more byte, or
// an unterminated line that reaches max, is refused).
func TestReadBoundedLine_Bounds(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"terminated at max", strings.Repeat("a", 99) + "\n", true},
		{"terminated over max", strings.Repeat("a", 100) + "\n", false},
		{"unterminated under max", strings.Repeat("a", 99), true},
		{"unterminated at max", strings.Repeat("a", 100), false},
		{"unterminated over max", strings.Repeat("a", 250), false},
	}
	for _, c := range cases {
		r := bufio.NewReaderSize(strings.NewReader(c.in), 16)
		_, _, err := readBoundedLine(r, 100)
		if (err == nil || errors.Is(err, io.EOF)) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}
