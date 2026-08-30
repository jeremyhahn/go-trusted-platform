// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// mediaStatusServer serves /media/status from a sequence of responses,
// one per request, repeating the last one forever.
func mediaStatusServer(t *testing.T, hits *atomic.Int64, responses ...func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != mediaStatusPath || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		n := int(hits.Add(1)) - 1
		if n >= len(responses) {
			n = len(responses) - 1
		}
		responses[n](w)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func statusJSON(files ...ipxe.MediaOpen) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(ipxe.MediaStatus{DataDir: "/data", Files: files}); err != nil {
			panic(err)
		}
	}
}

func statusCode(code int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

// smbdOpen builds the ISO's record as the watcher reports it while smbd
// is reading it: one open event and activity samples since.
func smbdOpen(path string, activity int) ipxe.MediaOpen {
	return ipxe.MediaOpen{Path: path, Opens: 1, MaxPos: 2048, OpenSamples: activity,
		Openers: []ipxe.MediaOpener{{Name: "smbd", Opens: 1, OpenSamples: activity, OpenEvents: 1, PosChanges: activity - 1, MaxPos: 2048, LastActivity: time.Now()}}}
}

func TestMediaReadProbeWait_ObservedOnFirstProbe(t *testing.T) {
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits, statusJSON(smbdOpen("/data/platform.iso", 1)))
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Hour}

	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Supported || !res.Observed {
		t.Fatalf("expected supported+observed, got %+v", res)
	}
	if res.Opens != 1 || res.MaxPos != 2048 {
		t.Errorf("expected opens=1 max_pos=2048, got %+v", res)
	}
	if hits.Load() != 1 {
		t.Errorf("expected exactly one probe, got %d", hits.Load())
	}
}

func TestMediaReadProbeWait_ObservedAfterRetries(t *testing.T) {
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits,
		statusJSON(),
		statusCode(http.StatusBadGateway),
		statusJSON(smbdOpen("/data/other.iso", 3)),
		statusJSON(smbdOpen("/data/platform.iso (deleted)", 2)),
	)
	p := &MediaReadProbe{BaseURL: srv.URL + "/", ISOName: "platform.iso", Interval: time.Millisecond}

	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Observed {
		t.Fatalf("expected the deleted-suffixed ISO entry to count, got %+v", res)
	}
	if hits.Load() != 4 {
		t.Errorf("expected 4 probes (empty, 502, other ISO, hit), got %d", hits.Load())
	}
}

func TestMediaReadProbeWait_UnsupportedEndpointReturnsImmediately(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		var hits atomic.Int64
		srv := mediaStatusServer(t, &hits, statusCode(code))
		p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Hour}

		res, err := p.Wait(t.Context())
		if err != nil {
			t.Fatalf("status %d: unexpected error: %v", code, err)
		}
		if res.Supported || res.Observed {
			t.Fatalf("status %d: expected unsupported+unobserved, got %+v", code, res)
		}
		if hits.Load() != 1 {
			t.Errorf("status %d: expected one probe, got %d", code, hits.Load())
		}
	}
}

func TestMediaReadProbeWait_TimesOutWhenNeverOpened(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var hits atomic.Int64
	// The sink never reports the ISO open; the third probe cancels the
	// context from inside the handler, so the timeout path is exercised
	// deterministically after a known number of polls.
	empty := statusJSON()
	srv := mediaStatusServer(t, &hits, func(w http.ResponseWriter) {
		if hits.Load() >= 3 {
			cancel()
		}
		empty(w)
	})
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}

	res, err := p.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if res.Observed || !res.Supported {
		t.Errorf("expected supported+unobserved on timeout, got %+v", res)
	}
	if hits.Load() < 3 {
		t.Errorf("expected at least 3 probes before cancellation, got %d", hits.Load())
	}
	if res.Elapsed <= 0 {
		t.Error("elapsed should be recorded")
	}
}

func TestMediaReadProbeWait_MalformedBodyKeepsPolling(t *testing.T) {
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits,
		func(w http.ResponseWriter) { w.Write([]byte("{not json")) },
		statusJSON(smbdOpen("/data/platform.iso", 1)),
	)
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}
	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Observed || hits.Load() != 2 {
		t.Fatalf("expected observation on the second probe, got %+v after %d probes", res, hits.Load())
	}
}

func TestMediaReadProbeWait_TransportErrorKeepsPolling(t *testing.T) {
	// A base URL nothing listens on: every probe is a transport error, and
	// the probe must keep going until the context ends rather than fail —
	// and a window that never got an answer is "no evidence", not "no
	// read".
	p := &MediaReadProbe{BaseURL: "http://127.0.0.1:1", ISOName: "platform.iso", Interval: time.Millisecond}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	res, err := p.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if res.Observed || res.Supported || res.Err == nil || res.ValidSamples != 0 {
		t.Errorf("an unanswered window is unsupported with its error kept, never observed: %+v", res)
	}
}

func TestMediaReadProbeWait_OnlySMBDCounts(t *testing.T) {
	var hits atomic.Int64
	checksum := ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1, OpenSamples: 9,
		Openers: []ipxe.MediaOpener{{Name: "sha256sum", Opens: 1, OpenSamples: 9, OpenEvents: 1, PosChanges: 8, LastActivity: time.Now()}}}
	both := checksum
	both.Openers = append([]ipxe.MediaOpener{{Name: "smbd", Opens: 1, OpenSamples: 1, OpenEvents: 1, LastActivity: time.Now()}}, both.Openers...)
	unnamed := ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1, OpenSamples: 1,
		Openers: []ipxe.MediaOpener{{Name: "", Opens: 1, OpenSamples: 1, OpenEvents: 1, LastActivity: time.Now()}}}
	srv := mediaStatusServer(t, &hits, statusJSON(checksum), statusJSON(unnamed), statusJSON(both))
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}
	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Observed || hits.Load() != 3 {
		t.Fatalf("a checksum or an unnamed holder is not a booting host; smbd is: %+v after %d probes", res, hits.Load())
	}
}

func TestMediaReadProbeWait_EmptyISONameMatchesAnyISO(t *testing.T) {
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits,
		statusJSON(smbdOpen("/data/vmlinuz", 1)),
		statusJSON(smbdOpen("/data/Operator-Inserted.ISO", 1)),
	)
	p := &MediaReadProbe{BaseURL: srv.URL, Interval: time.Millisecond}
	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Observed || hits.Load() != 2 {
		t.Fatalf("expected the out-of-band ISO to be matched by suffix: %+v after %d probes", res, hits.Load())
	}
}

func TestMediaReadProbeWait_SinceFiltersEarlierAttempts(t *testing.T) {
	now := time.Now()
	stale := smbdOpen("/data/platform.iso", 40)
	stale.Openers[0].LastActivity = now.Add(-time.Minute)
	fresh := smbdOpen("/data/platform.iso", 41)
	fresh.Openers[0].LastActivity = now.Add(time.Second)
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits, statusJSON(stale), statusJSON(fresh))
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Since: now, Interval: time.Millisecond}
	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Observed || hits.Load() != 2 {
		t.Fatalf("activity from before this attempt must not count; fresh activity must: %+v after %d probes", res, hits.Load())
	}
	probe := &MediaReadProbe{Since: now}
	if _, _, ok := probe.observed(ipxe.MediaOpen{Openers: []ipxe.MediaOpener{{Name: "smbd", LastActivity: now}}}, time.Time{}); ok {
		t.Error("no activity: not observed")
	}
	if _, _, ok := probe.observed(ipxe.MediaOpen{Openers: []ipxe.MediaOpener{{Name: "smbd", OpenEvents: 1, LastActivity: now.Add(-mediaReadSlack)}}}, time.Time{}); !ok {
		t.Error("activity inside the slack window counts")
	}
}

func TestMediaReadProbe_BaselineCursor(t *testing.T) {
	now := time.Now()
	watcher := now.Add(-time.Hour)
	held := ipxe.MediaOpen{Openers: []ipxe.MediaOpener{{Name: "smbd", OpenEvents: 1, PosChanges: 499, LastActivity: now}}}
	same := &MediaReadProbe{Since: now, Baseline: &MediaReadBaseline{Supported: true, WatcherSince: watcher, Activity: 500}}
	if _, _, ok := same.observed(held, watcher); ok {
		t.Error("no new activity since the baseline: not observed")
	}
	held.Openers[0].PosChanges = 500
	if _, _, ok := same.observed(held, watcher); !ok {
		t.Error("one position change past the baseline is observed")
	}
	// A different process's activity after the baseline does not move
	// smbd's counter, so historical smbd presence cannot be borrowed.
	borrowed := ipxe.MediaOpen{Openers: []ipxe.MediaOpener{
		{Name: "sha256sum", OpenEvents: 1, PosChanges: 30, LastActivity: now},
		{Name: "smbd", OpenEvents: 1, PosChanges: 499, LastActivity: now.Add(-time.Hour)},
	}}
	if _, _, ok := same.observed(borrowed, watcher); ok {
		t.Error("another process reading after the baseline is not smbd activity")
	}
	restarted := &MediaReadProbe{Since: now, Baseline: &MediaReadBaseline{Supported: true, WatcherSince: watcher, Activity: 500}}
	if _, _, ok := restarted.observed(ipxe.MediaOpen{Openers: []ipxe.MediaOpener{{Name: "smbd", OpenEvents: 1, LastActivity: now}}}, now.Add(-time.Minute)); !ok {
		t.Error("a baseline from a different watcher instance is ignored")
	}
	unsupported := &MediaReadProbe{Since: now, Baseline: &MediaReadBaseline{}}
	if _, _, ok := unsupported.observed(ipxe.MediaOpen{Openers: []ipxe.MediaOpener{{Name: "smbd", OpenEvents: 1, LastActivity: now}}}, watcher); !ok {
		t.Error("an unsupported baseline imposes no floor")
	}
}

func TestMediaReadProbe_ClientAttribution(t *testing.T) {
	now := time.Now()
	// Two BMCs read the same ISO. Node B's probe must see only B's worker.
	shared := ipxe.MediaOpen{Openers: []ipxe.MediaOpener{
		{Name: "smbd", Client: "198.18.1.103", OpenEvents: 1, PosChanges: 300, LastActivity: now},
		{Name: "smbd", Client: "198.18.1.104", OpenEvents: 1, PosChanges: 0, LastActivity: now.Add(-time.Hour)},
	}}
	nodeB := &MediaReadProbe{Client: "198.18.1.104", Since: now, Baseline: &MediaReadBaseline{Supported: true, Activity: 1}}
	if activity, _, ok := nodeB.observed(shared, time.Time{}); ok || activity != 1 {
		t.Errorf("node A's reads must not count for node B: activity=%d ok=%v", activity, ok)
	}
	nodeA := &MediaReadProbe{Client: "198.18.1.103", Since: now, Baseline: &MediaReadBaseline{Supported: true, Activity: 1}}
	if activity, _, ok := nodeA.observed(shared, time.Time{}); !ok || activity != 301 {
		t.Errorf("node A's own reads count for node A: activity=%d ok=%v", activity, ok)
	}
	// A record whose smbd workers carry no client tags (an smbd that does
	// not retitle) cannot be attributed; every worker counts.
	untagged := ipxe.MediaOpen{Openers: []ipxe.MediaOpener{{Name: "smbd", OpenEvents: 1, PosChanges: 5, LastActivity: now}}}
	if _, _, ok := nodeB.observed(untagged, time.Time{}); !ok {
		t.Error("without client tags every smbd worker counts")
	}
	// A probe with no client of its own counts every worker too.
	anyClient := &MediaReadProbe{Since: now}
	if activity, _, ok := anyClient.observed(shared, time.Time{}); !ok || activity != 302 {
		t.Errorf("no client on the probe: all workers count, activity=%d", activity)
	}
}

func TestMediaReadProbe_Snapshot(t *testing.T) {
	since := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(ipxe.MediaStatus{DataDir: "/data", Since: since,
			Files: []ipxe.MediaOpen{{Path: "/data/platform.iso", Openers: []ipxe.MediaOpener{
				{Name: "tar", OpenEvents: 5}, {Name: "smbd", Client: "10.0.0.1", OpenEvents: 2, PosChanges: 40},
				{Name: "smbd", Client: "10.0.0.2", OpenEvents: 1, PosChanges: 9}}}}}); err != nil {
			panic(err)
		}
	})
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Client: "10.0.0.1"}
	b, err := p.Snapshot(t.Context())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !b.Supported || b.Activity != 42 || !b.WatcherSince.Equal(since) {
		t.Errorf("baseline must carry this client's smbd activity only: %+v", b)
	}

	var hits404 atomic.Int64
	srv404 := mediaStatusServer(t, &hits404, statusCode(http.StatusNotFound))
	b, err = (&MediaReadProbe{BaseURL: srv404.URL, ISOName: "platform.iso"}).Snapshot(t.Context())
	if err != nil || b.Supported {
		t.Errorf("unsupported endpoint: %+v %v", b, err)
	}

	var hits503 atomic.Int64
	srv503 := mediaStatusServer(t, &hits503, statusCode(http.StatusServiceUnavailable))
	_, err = (&MediaReadProbe{BaseURL: srv503.URL, ISOName: "platform.iso"}).Snapshot(t.Context())
	var unavailable ErrMediaStatusUnavailable
	if !errors.As(err, &unavailable) || unavailable.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected ErrMediaStatusUnavailable{503}, got %v", err)
	}
	if _, err := (&MediaReadProbe{BaseURL: "http://127.0.0.1:1"}).Snapshot(t.Context()); err == nil {
		t.Error("transport failure is an error")
	}
	if b, err := (&MediaReadProbe{BaseURL: srv.URL, ISOName: "absent.iso"}).Snapshot(t.Context()); err != nil || b.Activity != 0 {
		t.Errorf("an ISO never seen has zero baseline activity: %+v %v", b, err)
	}
}

func TestMediaReadProbeWait_NoValidAnswerIsUnsupported(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var hits atomic.Int64
	// Only 5xx and garbage: the window closes without a usable sample,
	// which must read as "no evidence", never as "never read".
	srv := mediaStatusServer(t, &hits,
		statusCode(http.StatusServiceUnavailable),
		func(w http.ResponseWriter) { w.Write([]byte("<html>gateway error</html>")) },
		func(w http.ResponseWriter) {
			if hits.Load() >= 3 {
				cancel()
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	)
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}
	res, err := p.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the context error, got %v", err)
	}
	if res.Supported || res.Observed || res.ValidSamples != 0 || res.Err == nil {
		t.Fatalf("a window with no valid sample must be unsupported with the last error kept: %+v", res)
	}
}

func TestMediaReadProbeWait_OneValidAnswerKeepsSupport(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits, statusJSON(), func(w http.ResponseWriter) {
		if hits.Load() >= 3 {
			cancel()
		}
		w.WriteHeader(http.StatusBadGateway)
	})
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}
	res, err := p.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the window ending is the cancellation, got %v", err)
	}
	if !res.Supported || res.Observed || res.ValidSamples != 1 || res.Err != nil {
		t.Fatalf("one decoded answer showing no read is real evidence, and a later outage is not the result: %+v", res)
	}
}

func TestSameClient(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"198.18.1.103", "198.18.1.103", true},
		{"198.18.1.103:445", "198.18.1.103", true},
		{"[fe80::1]:445", "fe80::1", true},
		{"fe80:0:0:0:0:0:0:1", "fe80::1", true},
		{"198.18.1.103", "198.18.1.104", false},
		{"bmc-02.mgmt", "bmc-02.mgmt", true},
		{"bmc-02.mgmt", "bmc-03.mgmt", false},
	}
	for _, tc := range cases {
		if got := sameClient(tc.a, tc.b); got != tc.want {
			t.Errorf("sameClient(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMediaReadProbe_MixedTaggingIsFailSafe(t *testing.T) {
	// One smbd worker carries a client tag and another does not: the
	// record is treated as attributable, so the untagged worker cannot
	// be borrowed by any node. A node whose own worker is the untagged
	// one therefore sees no evidence — never-read, not a false pass.
	now := time.Now()
	mixed := ipxe.MediaOpen{Openers: []ipxe.MediaOpener{
		{Name: "smbd", OpenEvents: 1, PosChanges: 50, LastActivity: now},
		{Name: "smbd", Client: "198.18.1.103", OpenEvents: 1, LastActivity: now},
	}}
	p := &MediaReadProbe{Client: "198.18.1.104", Since: now}
	if activity, _, ok := p.observed(mixed, time.Time{}); ok || activity != 0 {
		t.Errorf("an untagged worker must not stand in for a node's own: activity=%d ok=%v", activity, ok)
	}
}

func TestMediaReadProbeWait_OutageAfterEarlyAnswerIsUnsupported(t *testing.T) {
	// One decoded answer at the start, then nothing usable for the rest
	// of the window: the stretch where a slow POST would have read the
	// media was never observed, so this is no evidence, not never-read.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var hits atomic.Int64
	srv := mediaStatusServer(t, &hits, statusJSON(), func(w http.ResponseWriter) {
		if hits.Load() >= int64(mediaReadStaleProbes)+4 {
			cancel()
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}
	res, err := p.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the window ending is the cancellation, got %v", err)
	}
	if res.Supported || res.Observed || res.ValidSamples != 1 || res.Err == nil {
		t.Fatalf("an early answer followed by a long outage is unsupported with the error kept: %+v", res)
	}
}

func TestMediaReadProbeWait_MidWindowOutageKeepsCumulativeEvidence(t *testing.T) {
	// The endpoint is unreachable for a stretch in the middle of the
	// window while the host starts reading; the watcher's record is
	// cumulative, so the first decoded answer after the outage carries
	// the read and the probe observes it.
	var hits atomic.Int64
	//nolint:gocritic // four consecutive 503s are the outage
	srv := mediaStatusServer(t, &hits,
		statusJSON(),
		statusCode(http.StatusServiceUnavailable),
		statusCode(http.StatusServiceUnavailable),
		statusCode(http.StatusServiceUnavailable),
		statusCode(http.StatusServiceUnavailable),
		statusJSON(smbdOpen("/data/platform.iso", 3)),
	)
	p := &MediaReadProbe{BaseURL: srv.URL, ISOName: "platform.iso", Interval: time.Millisecond}
	res, err := p.Wait(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Supported || !res.Observed || res.ValidSamples != 2 || hits.Load() != 6 {
		t.Fatalf("a read during a mid-window outage is on the next record: %+v after %d probes", res, hits.Load())
	}
}
