package resume

import (
	"strings"
	"testing"
	"time"

	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/snapshot"
	"github.com/vasic-digital/continuum/pkg/store"
)

func engineWith(t *testing.T, sts ...model.StreamState) *snapshot.Engine {
	t.Helper()
	s, _ := store.Open(t.TempDir())
	e := snapshot.New(s, "test", 0)
	for _, st := range sts {
		if err := e.Set(st); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Commit("c"); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRenderMetricAndDeterminism(t *testing.T) {
	e := engineWith(t,
		model.StreamState{StreamID: "T1/main", Kind: "main", NextAction: "flash"},
		model.StreamState{StreamID: "T2/feat", Kind: "track", NextAction: "code"},
		model.StreamState{StreamID: "agent:x", Kind: "agent", NextAction: "review"},
	)
	b, err := Render(e, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Metric.Streams != 3 {
		t.Fatalf("streams=%d", b.Metric.Streams)
	}
	// resume reads ONLY the manifest (1) + one blob per stream — this is the
	// token-cost win, not O(history).
	if b.Metric.BlobsRead != 1+3 {
		t.Fatalf("blobs read=%d want 4", b.Metric.BlobsRead)
	}
	if b.Metric.Bytes == 0 || b.Metric.EstTokens == 0 {
		t.Fatal("metric bytes/tokens must be >0")
	}
	if !strings.Contains(b.Full, "T1/main") || !strings.Contains(b.Full, "agent:x") {
		t.Fatal("FULL bundle missing streams")
	}
	// determinism: re-render byte-identical (§11.4.201).
	b2, _ := Render(e, "", Options{})
	if b.Full != b2.Full {
		t.Fatal("FULL render is not deterministic")
	}
	// the volatile line must NOT be inside the deterministic body.
	if strings.Contains(b.Full, "generated-at") {
		t.Fatal("volatile generated-at leaked into deterministic FULL body")
	}
	if !strings.HasPrefix(GeneratedAtLine(time.Now()), "generated-at: ") {
		t.Fatal("GeneratedAtLine format")
	}
}

func TestBlockedFirst(t *testing.T) {
	e := engineWith(t,
		model.StreamState{StreamID: "aaa", Kind: "track", NextAction: "n1"},
		model.StreamState{StreamID: "zzz", Kind: "track", NextAction: "n2", Blockers: []string{"needs operator"}},
	)
	b, _ := Render(e, "", Options{})
	// The blocked stream (zzz) must be the SHORT top despite sorting after aaa.
	if !strings.Contains(b.Short, "zzz") {
		t.Fatalf("blocked stream not surfaced first: %q", b.Short)
	}
	if !strings.Contains(b.Short, "[1 blocked]") {
		t.Fatalf("blocked count missing: %q", b.Short)
	}
}

func TestResumeEmpty(t *testing.T) {
	s, _ := store.Open(t.TempDir())
	e := snapshot.New(s, "test", 0)
	b, err := Render(e, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Metric.Streams != 0 || !strings.Contains(b.Short, "no committed streams") {
		t.Fatalf("empty resume wrong: %q", b.Short)
	}
}
