// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gateTestLogger discards output so tests stay quiet.
func gateTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// fakeAttestationClient is a configurable AttestationClient counting calls.
type fakeAttestationClient struct {
	manifests []*platformv1.HostManifest
	listErr   error
	status    platformv1.ManifestVerificationStatus
	verifyErr error

	// block, when non-nil, is closed by the test to release in-flight
	// ListManifests calls (used to prove singleflight deduplication);
	// started is closed once the first ListManifests call is in flight.
	block   chan struct{}
	started chan struct{}
	once    sync.Once

	mu          sync.Mutex
	listCalls   int
	verifyCalls int
	lastList    *platformv1.ListManifestsRequest
}

func (f *fakeAttestationClient) ListManifests(ctx context.Context, req *platformv1.ListManifestsRequest) ([]*platformv1.HostManifest, uint32, error) {
	f.mu.Lock()
	f.listCalls++
	f.lastList = req
	block := f.block
	f.mu.Unlock()
	if f.started != nil {
		f.once.Do(func() { close(f.started) })
	}
	if block != nil {
		<-block
	}
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.manifests, uint32(len(f.manifests)), nil
}

func (f *fakeAttestationClient) VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.ManifestVerificationResult, error) {
	f.mu.Lock()
	f.verifyCalls++
	f.mu.Unlock()
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return &platformv1.ManifestVerificationResult{Status: f.status}, nil
}

func (f *fakeAttestationClient) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls, f.verifyCalls
}

// manifestAt builds a host manifest collected at the given time.
func manifestAt(hostID string, ts time.Time) *platformv1.HostManifest {
	return &platformv1.HostManifest{
		Id:        "m-" + hostID,
		HostId:    hostID,
		Timestamp: timestamppb.New(ts),
	}
}

// testClock is a settable clock for deterministic cache expiry.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newGate(t *testing.T, client AttestationClient, clock *testClock) *SDKAttestationGate {
	t.Helper()
	g, err := NewSDKAttestationGate(SDKAttestationGateConfig{
		Client: client,
		Clock:  clock.Now,
		Logger: gateTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewSDKAttestationGate: %v", err)
	}
	return g
}

func TestNewSDKAttestationGateNilClient(t *testing.T) {
	if _, err := NewSDKAttestationGate(SDKAttestationGateConfig{}); err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestSDKAttestationGateFresh(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	client := &fakeAttestationClient{
		manifests: []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-time.Hour))},
		status:    platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
	}
	gate := newGate(t, client, clock)

	if err := gate.Fresh(context.Background(), "lab-node-2", 24*time.Hour); err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	if client.lastList.GetHostId() != "lab-node-2" || client.lastList.GetLimit() != 1 {
		t.Errorf("list request = %+v", client.lastList)
	}
}

func TestSDKAttestationGateStaleVerdicts(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	verified := platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED
	failed := platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_FAILED
	tests := []struct {
		name   string
		client *fakeAttestationClient
		maxAge time.Duration
	}{
		{
			"no manifests",
			&fakeAttestationClient{status: verified},
			time.Hour,
		},
		{
			"manifest without timestamp",
			&fakeAttestationClient{
				manifests: []*platformv1.HostManifest{{Id: "m", HostId: "lab-node-2"}},
				status:    verified,
			},
			time.Hour,
		},
		{
			"verification rejected",
			&fakeAttestationClient{
				manifests: []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-time.Minute))},
				status:    failed,
			},
			time.Hour,
		},
		{
			"manifest older than max age",
			&fakeAttestationClient{
				manifests: []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-2*time.Hour))},
				status:    verified,
			},
			time.Hour,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gate := newGate(t, tc.client, &testClock{now: base})
			err := gate.Fresh(context.Background(), "lab-node-2", tc.maxAge)
			if err == nil {
				t.Fatal("expected stale error")
			}
			if !errors.Is(err, proxy.ErrAttestationStale) {
				t.Errorf("error = %v, want wrapping proxy.ErrAttestationStale", err)
			}
			var notAttested *ErrDeviceNotAttested
			if !errors.As(err, &notAttested) {
				t.Errorf("error = %T, want *ErrDeviceNotAttested", err)
			}
		})
	}
}

func TestSDKAttestationGateQueryFailures(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		client *fakeAttestationClient
	}{
		{"list error", &fakeAttestationClient{listErr: errors.New("platformd down")}},
		{
			"verify error",
			&fakeAttestationClient{
				manifests: []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-time.Minute))},
				verifyErr: errors.New("platformd down"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gate := newGate(t, tc.client, &testClock{now: base})
			err := gate.Fresh(context.Background(), "lab-node-2", time.Hour)
			if err == nil {
				t.Fatal("expected query failure")
			}
			if errors.Is(err, proxy.ErrAttestationStale) {
				t.Error("query failures must NOT map to the stale verdict")
			}
			var queryErr *ErrAttestationQueryFailed
			if !errors.As(err, &queryErr) {
				t.Errorf("error = %T, want *ErrAttestationQueryFailed", err)
			}
		})
	}
}

func TestSDKAttestationGateEmptyDeviceID(t *testing.T) {
	gate := newGate(t, &fakeAttestationClient{}, &testClock{now: time.Now()})
	err := gate.Fresh(context.Background(), "", time.Hour)
	var queryErr *ErrAttestationQueryFailed
	if !errors.As(err, &queryErr) {
		t.Fatalf("error = %v, want *ErrAttestationQueryFailed", err)
	}
	if list, _ := (&fakeAttestationClient{}).counts(); list != 0 {
		t.Error("no query must be issued for an empty device id")
	}
}

func TestSDKAttestationGateVerdictCache(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	client := &fakeAttestationClient{
		manifests: []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-time.Minute))},
		status:    platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
	}
	gate := newGate(t, client, clock)

	for i := 0; i < 5; i++ {
		if err := gate.Fresh(context.Background(), "lab-node-2", time.Hour); err != nil {
			t.Fatalf("Fresh #%d: %v", i, err)
		}
	}
	if list, verify := client.counts(); list != 1 || verify != 1 {
		t.Errorf("calls = (%d, %d), want one platformd round trip within the TTL", list, verify)
	}

	// One cached verdict serves different per-route max ages.
	if err := gate.Fresh(context.Background(), "lab-node-2", 30*time.Second); !errors.Is(err, proxy.ErrAttestationStale) {
		t.Errorf("tight max age on cached verdict = %v, want stale", err)
	}

	// TTL expiry triggers exactly one refresh.
	clock.Advance(DefaultAttestationCacheTTL + time.Second)
	if err := gate.Fresh(context.Background(), "lab-node-2", time.Hour); err != nil {
		t.Fatalf("Fresh after expiry: %v", err)
	}
	if list, _ := client.counts(); list != 2 {
		t.Errorf("list calls = %d, want refresh after TTL", list)
	}
}

func TestSDKAttestationGateNegativeCache(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	client := &fakeAttestationClient{listErr: errors.New("platformd down")}
	gate := newGate(t, client, clock)

	for i := 0; i < 3; i++ {
		if err := gate.Fresh(context.Background(), "lab-node-2", time.Hour); err == nil {
			t.Fatal("expected cached failure")
		}
	}
	if list, _ := client.counts(); list != 1 {
		t.Errorf("list calls = %d, want failures cached within the negative TTL", list)
	}

	// Errors must not outlive the short negative TTL.
	clock.Advance(DefaultAttestationNegativeTTL + time.Second)
	client.mu.Lock()
	client.listErr = nil
	client.manifests = []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-time.Minute))}
	client.status = platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED
	client.mu.Unlock()
	if err := gate.Fresh(context.Background(), "lab-node-2", time.Hour); err != nil {
		t.Fatalf("Fresh after recovery: %v", err)
	}
}

func TestSDKAttestationGateSingleflight(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	client := &fakeAttestationClient{
		manifests: []*platformv1.HostManifest{manifestAt("lab-node-2", base.Add(-time.Minute))},
		status:    platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
		block:     make(chan struct{}),
		started:   make(chan struct{}),
	}
	gate := newGate(t, client, clock)

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- gate.Fresh(context.Background(), "lab-node-2", time.Hour)
		}()
	}
	// Let the flight leader block inside ListManifests, then release all.
	<-client.started
	close(client.block)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Fresh: %v", err)
		}
	}
	if list, _ := client.counts(); list != 1 {
		t.Errorf("list calls = %d, want singleflight to dedupe concurrent refreshes", list)
	}
}

func TestLazyAttestationClient(t *testing.T) {
	if _, err := NewLazyAttestationClient(nil); err == nil {
		t.Fatal("expected error for nil dial func")
	}

	t.Run("dial error surfaces and retries", func(t *testing.T) {
		dials := 0
		fail := true
		lazy, err := NewLazyAttestationClient(func(ctx context.Context) (AttestationClient, error) {
			dials++
			if fail {
				return nil, errors.New("connection refused")
			}
			return &fakeAttestationClient{
				status: platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
			}, nil
		})
		if err != nil {
			t.Fatalf("NewLazyAttestationClient: %v", err)
		}
		if _, _, err := lazy.ListManifests(context.Background(), &platformv1.ListManifestsRequest{}); err == nil {
			t.Fatal("expected dial failure")
		} else {
			var dialErr *ErrDialFailed
			if !errors.As(err, &dialErr) {
				t.Errorf("error = %T, want *ErrDialFailed", err)
			}
		}
		fail = false
		if _, _, err := lazy.ListManifests(context.Background(), &platformv1.ListManifestsRequest{}); err != nil {
			t.Fatalf("ListManifests after recovery: %v", err)
		}
		if _, err := lazy.VerifyManifest(context.Background(), &platformv1.VerifyManifestRequest{}); err != nil {
			t.Fatalf("VerifyManifest: %v", err)
		}
		if dials != 2 {
			t.Errorf("dials = %d, want one failed and one cached successful dial", dials)
		}
	})
}
