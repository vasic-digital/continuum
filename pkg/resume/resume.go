// Package resume renders the compact, structured resume bundle a fresh session
// (or the ruler) reads INSTEAD of re-reading everything — the core token-cost
// win of continuum.
//
// The bundle has two variants (§11.4.127): a one-line SHORT first sentence and
// a bounded, structured FULL block. Both are assembled by reading ONLY the
// latest snapshot manifest plus one compact blob per stream — never the event
// history — so the resume read cost is O(sum of per-stream compact states), not
// O(full history). A measured Metric accompanies every render as captured
// evidence of that cost (§11.4.5/§11.4.69).
//
// Determinism (§11.4.201): the FULL block is deterministic in committed state.
// The only volatile line (generated-at) is emitted OUTSIDE the deterministic
// body, clearly marked, so a re-render byte-compares against committed state.
package resume

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vasic-digital/continuum/pkg/hash"
	"github.com/vasic-digital/continuum/pkg/model"
	"github.com/vasic-digital/continuum/pkg/snapshot"
)

// Metric is the captured resume-cost evidence.
type Metric struct {
	SnapshotID string `json:"snapshot_id"`
	Streams    int    `json:"streams"`
	BlobsRead  int    `json:"blobs_read"` // manifest (1) + one per stream
	Bytes      int    `json:"bytes"`      // size of the FULL bundle body
	EstTokens  int    `json:"est_tokens"` // Bytes/4 heuristic (documented approximation)
	WallMicros int64  `json:"wall_micros"`
}

// Bundle is the rendered resume output.
type Bundle struct {
	Short  string
	Full   string // deterministic body (no volatile lines)
	Metric Metric
}

// Options tune the render.
type Options struct {
	// MaxStreams caps how many streams the FULL block enumerates (0 = all).
	// Streams are prioritized (blocked first) so the cap never drops a blocker.
	MaxStreams int
	// Title is the heading of the FULL block (default "Resume").
	Title string
}

// Render reads the latest committed snapshot (or the given id) and produces the
// bundle. It reads the manifest and one blob per stream — nothing else.
func Render(e *snapshot.Engine, snapID string, opts Options) (Bundle, error) {
	start := time.Now()
	states, id, err := e.RestoreAll(snapID)
	if err != nil {
		return Bundle{}, err
	}
	if opts.Title == "" {
		opts.Title = "Resume"
	}

	ordered := prioritize(states)
	shown := ordered
	if opts.MaxStreams > 0 && len(shown) > opts.MaxStreams {
		shown = shown[:opts.MaxStreams]
	}

	full := renderFull(id, ordered, shown, opts)
	short := renderShort(id, ordered)

	m := Metric{
		SnapshotID: id,
		Streams:    len(states),
		BlobsRead:  1 + len(states),
		Bytes:      len(full),
		EstTokens:  (len(full) + 3) / 4,
		WallMicros: time.Since(start).Microseconds(),
	}
	return Bundle{Short: short, Full: full, Metric: m}, nil
}

// prioritize orders streams blocked-first, then by StreamID (deterministic).
func prioritize(states map[string]model.StreamState) []model.StreamState {
	out := make([]model.StreamState, 0, len(states))
	for _, s := range states {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		bi, bj := len(out[i].Blockers) > 0, len(out[j].Blockers) > 0
		if bi != bj {
			return bi // blocked streams first
		}
		return out[i].StreamID < out[j].StreamID
	})
	return out
}

func renderShort(id string, ordered []model.StreamState) string {
	if len(ordered) == 0 {
		return "Resume: no committed streams — nothing to restore."
	}
	top := ordered[0]
	next := top.NextAction
	if next == "" {
		next = "(no next action recorded)"
	}
	blocked := 0
	for _, s := range ordered {
		if len(s.Blockers) > 0 {
			blocked++
		}
	}
	blk := ""
	if blocked > 0 {
		blk = fmt.Sprintf(" [%d blocked]", blocked)
	}
	return fmt.Sprintf("Resume %d stream(s) from snapshot %s%s — top: %s (%s) → %s",
		len(ordered), hash.Short(id, 12), blk, top.StreamID, top.Kind, next)
}

// renderFull produces the deterministic FULL body (no volatile lines).
func renderFull(id string, all, shown []model.StreamState, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", opts.Title)
	fmt.Fprintf(&b, "Snapshot: %s\n", id)
	fmt.Fprintf(&b, "Streams:  %d (showing %d)\n\n", len(all), len(shown))
	for _, s := range shown {
		fmt.Fprintf(&b, "## %s  [%s]", s.StreamID, s.Kind)
		if s.Owner != "" {
			fmt.Fprintf(&b, "  (owner: %s)", s.Owner)
		}
		b.WriteString("\n")
		writeField(&b, "Phase", s.Phase)
		writeField(&b, "Next", s.NextAction)
		writeField(&b, "Goal", s.Goal)
		writeField(&b, "Head", s.Head)
		if len(s.InFlight) > 0 {
			b.WriteString("- In-flight:\n")
			jobs := append([]model.Job(nil), s.InFlight...)
			sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
			for _, j := range jobs {
				fmt.Fprintf(&b, "  - %s %s (log: %s)\n", j.Kind, j.ID, j.Log)
			}
		}
		writeList(&b, "Blockers", s.Blockers)
		writeList(&b, "Evidence", s.Evidence)
		writeList(&b, "Constraints", s.Constraints)
		if len(s.Fields) > 0 {
			keys := make([]string, 0, len(s.Fields))
			for k := range s.Fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteString("- Fields:\n")
			for _, k := range keys {
				fmt.Fprintf(&b, "  - %s: %s\n", k, s.Fields[k])
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func writeField(b *strings.Builder, label, v string) {
	if v == "" {
		return
	}
	fmt.Fprintf(b, "- %s: %s\n", label, v)
}

func writeList(b *strings.Builder, label string, xs []string) {
	if len(xs) == 0 {
		return
	}
	fmt.Fprintf(b, "- %s:\n", label)
	for _, x := range xs {
		fmt.Fprintf(b, "  - %s\n", x)
	}
}

// GeneratedAtLine returns the single volatile line to print OUTSIDE the
// deterministic body (§11.4.201/§11.4.205(5)). The engine never puts this
// inside Full, so verify can byte-compare Full against committed state.
func GeneratedAtLine(now time.Time) string {
	return "generated-at: " + now.UTC().Format(time.RFC3339)
}
