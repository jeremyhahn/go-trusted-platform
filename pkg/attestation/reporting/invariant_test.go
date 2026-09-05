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

package reporting

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingSource records every device it was asked to quote. It is the
// tripwire for the invariant: if any request path reaches a device, this
// counter moves.
type countingSource struct {
	mu       chan struct{}
	calls    []string
	evidence []byte
	err      error
}

func newCountingSource() *countingSource {
	return &countingSource{mu: make(chan struct{}, 1), evidence: []byte(`{"quote":"x"}`)}
}

func (s *countingSource) Collect(_ context.Context, deviceID string, nonce []byte) ([]byte, error) {
	s.mu <- struct{}{}
	s.calls = append(s.calls, deviceID)
	<-s.mu
	if s.err != nil {
		return nil, s.err
	}
	return s.evidence, nil
}

func (s *countingSource) count() int {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	return len(s.calls)
}

type stubVerifier struct {
	report *Report
	err    error
}

func (v *stubVerifier) VerifyDeviceQuote(_ context.Context, deviceID string, _ []byte) (*Report, error) {
	if v.err != nil {
		return nil, v.err
	}
	r := *v.report
	r.DeviceID = deviceID
	return &r, nil
}

// TestInvariant_ReaderCannotReachADevice is THE test for #226's hard
// requirement: "a client request must NEVER cause a direct TPM quote".
//
// It is a structural assertion, not a behavioural one, because a behavioural
// test only proves that today's handlers happen not to collect. The check is
// that the type a request handler is given — Reader — exposes no method
// capable of reaching a device, so wiring one up would require changing a
// signature rather than adding a line inside a method body.
//
// Enumerating Reader's methods by reflection rather than reading them means
// this fails when someone ADDS a method, which is the direction the invariant
// can be broken in.
func TestInvariant_ReaderCannotReachADevice(t *testing.T) {
	readerType := reflect.TypeOf((*Reader)(nil)).Elem()

	allowed := map[string]bool{"Report": true, "Reports": true}

	for i := 0; i < readerType.NumMethod(); i++ {
		m := readerType.Method(i)
		assert.True(t, allowed[m.Name],
			"Reader gained method %q. The read-only view given to request handlers must "+
				"expose nothing that can reach a device: adding a collecting or refreshing "+
				"method here is how a request comes to cause a TPM quote. Put it on "+
				"Collector instead.", m.Name)

		// No method on the read path may take a context. A context is the
		// signature of an operation that blocks on something external — which
		// a pure cache read never does, and a device round-trip always does.
		mt := m.Type
		for a := 0; a < mt.NumIn(); a++ {
			assert.NotEqual(t, "context.Context", mt.In(a).String(),
				"Reader.%s takes a context, which means it can block on something "+
					"external. A cache read cannot; a device round-trip must.", m.Name)
		}
	}
}

// TestInvariant_CacheHoldsNoQuoteSource asserts the cache cannot reach a
// device even by an unexported field.
//
// The Reader interface constrains what a handler may CALL; this constrains
// what the concrete type can REACH. Together they are the structural claim:
// there is no path, exported or not, from the object a handler holds to a
// device.
func TestInvariant_CacheHoldsNoQuoteSource(t *testing.T) {
	cacheType := reflect.TypeOf(Cache{})
	sourceType := reflect.TypeOf((*QuoteSource)(nil)).Elem()
	verifierType := reflect.TypeOf((*Verifier)(nil)).Elem()

	for i := 0; i < cacheType.NumField(); i++ {
		f := cacheType.Field(i)
		assert.False(t, f.Type == sourceType || f.Type.Implements(sourceType),
			"Cache.%s can reach a QuoteSource. The cache is what request handlers "+
				"read; giving it a way to a device defeats the invariant regardless "+
				"of whether today's code calls it.", f.Name)
		assert.False(t, f.Type == verifierType || f.Type.Implements(verifierType),
			"Cache.%s can reach a Verifier, which implies it can act on fresh "+
				"evidence rather than only serve stored verdicts.", f.Name)
	}
}

// TestInvariant_ServingFromCacheNeverQuotes is the behavioural half: reading
// the cache — hit, miss, and stale — must not move the source's counter.
//
// A miss is the interesting case. It is the moment where "just fetch it
// then" is the tempting implementation, and it must return "no report" rather
// than a fresh quote.
func TestInvariant_ServingFromCacheNeverQuotes(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())

	collector, err := newCollectorWithClock(Config{
		Source:   src,
		Verifier: &stubVerifier{report: &Report{Verified: true, Status: "verified"}},
		Interval: time.Minute,
	}, clk)
	require.NoError(t, err)

	var reader Reader = collector.Cache()

	// Miss.
	_, ok := reader.Report("never-collected")
	assert.False(t, ok, "a device with no report must report absence, not a synthesised verdict")
	assert.Empty(t, reader.Reports())

	// Populate exactly once, through the collector.
	collector.Collect(context.Background(), "dev-1")
	require.Equal(t, 1, src.count())

	// Hit.
	r, ok := reader.Report("dev-1")
	require.True(t, ok)
	assert.True(t, r.Verified)

	// Stale: age the clock past the TTL. A stale read still must not collect.
	clk.advance(collector.Cache().TTL() + time.Hour)
	assert.False(t, collector.Cache().Fresh("dev-1"), "the report should now be stale")
	r, ok = reader.Report("dev-1")
	require.True(t, ok, "a stale report is retained, not discarded — absence of evidence is not failed attestation")
	assert.True(t, r.Verified)

	// Every read above, across hit, miss and stale, added no quote.
	assert.Equal(t, 1, src.count(),
		"reading the cache must never reach a device; only the collector may")
}

// TestInvariant_UnreachableDeviceDoesNotBecomeAFailedVerdict is the rule the
// design of record states for quarantine, enforced here at its source: a
// device that could not be reached has produced NO evidence, which is not the
// same as evidence that failed.
//
// Getting this wrong quarantines healthy nodes on a network blip, which is
// what #197 shipped once.
func TestInvariant_UnreachableDeviceDoesNotBecomeAFailedVerdict(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	collector, err := newCollectorWithClock(Config{
		Source:   src,
		Verifier: &stubVerifier{report: &Report{Verified: true, Status: "verified"}},
		Interval: time.Minute,
	}, clk)
	require.NoError(t, err)

	// A good collection first.
	collector.Collect(context.Background(), "dev-1")
	before, ok := collector.Cache().Report("dev-1")
	require.True(t, ok)
	require.True(t, before.Verified)

	// Now the device becomes unreachable.
	src.err = errors.New("dial tcp: connection refused")
	collector.Collect(context.Background(), "dev-1")

	after, ok := collector.Cache().Report("dev-1")
	require.True(t, ok, "the previous report must be retained, not deleted")
	assert.True(t, after.Verified,
		"an unreachable device must NOT overwrite a good report with a failed verdict; "+
			"absence of evidence is not failed attestation")
	assert.Equal(t, before.CollectedAt, after.CollectedAt,
		"a failed collection must not restamp the report — that would make stale evidence look fresh")
}
