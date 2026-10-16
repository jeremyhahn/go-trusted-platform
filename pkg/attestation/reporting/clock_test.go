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
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Clock state on the wire (#509). The collector records the DEVICE's own
// clock trust state beside each verdict, because a machine that cannot place
// itself in time runs its certificate windows, DANE signatures and token
// checks against a clock the platform cannot vouch for.

// TestDecodeNodeClock_AcceptsBothWireShapes asserts the decoder reads the
// webservice envelope and the daemon listener's bare payload, since the two
// listeners serve the same route differently.
func TestDecodeNodeClock_AcceptsBothWireShapes(t *testing.T) {
	for name, body := range map[string]string{
		"webservice envelope": `{"code":200,"success":true,"payload":{"synced":true,"stratum":3}}`,
		"bare payload":        `{"synced":true,"stratum":3}`,
	} {
		t.Run(name, func(t *testing.T) {
			synced, err := decodeNodeClock([]byte(body))
			require.NoError(t, err)
			assert.True(t, synced)
		})
	}

	synced, err := decodeNodeClock([]byte(`{"synced":false,"leap_status":"Not synchronised"}`))
	require.NoError(t, err)
	assert.False(t, synced, "a node reporting an undisciplined clock is recorded as such")
}

// TestDecodeNodeClock_RefusesUnusableAnswers asserts every answer that is
// not a clock state is an ERROR, never a false. The collector turns an error
// into "unknown", and a false into "this machine's clock is wrong" — the two
// must not be reachable from the same input.
func TestDecodeNodeClock_RefusesUnusableAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":          `<html>404</html>`,
		"no synced field":   `{"stratum":3}`,
		"envelope failure":  `{"code":503,"success":false,"payload":{"synced":true}}`,
		"synced wrong type": `{"synced":"yes"}`,
	} {
		t.Run(name, func(t *testing.T) {
			synced, err := decodeNodeClock([]byte(body))
			var invalid ErrInvalidClockState
			require.ErrorAs(t, err, &invalid, "an unusable answer must be an error")
			assert.False(t, synced)
			assert.NotEmpty(t, invalid.Reason)
		})
	}
}

// TestNodeQuoteSource_ClockSyncedOverMTLS asserts the collector reads the
// node's clock state over the same authenticated path it collects quotes on.
func TestNodeQuoteSource_ClockSyncedOverMTLS(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal", Source: SourcePlatformDNS}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)

	synced, err := src.ClockSynced(context.Background(), "42")
	require.NoError(t, err)
	assert.True(t, synced)
	assert.Equal(t, int32(1), node.clockHits.Load())
}

// TestNodeQuoteSource_ClockSyncedReportsUnsynced asserts a node that admits
// an undisciplined clock is reported as such rather than hidden behind an
// error.
func TestNodeQuoteSource_ClockSyncedReportsUnsynced(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	node.respondClock = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"code":200,"success":true,"payload":{"synced":false,"leap_status":"Not synchronised"}}`))
		require.NoError(t, err)
	}
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal", Source: SourcePlatformDNS}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)

	synced, err := src.ClockSynced(context.Background(), "42")
	require.NoError(t, err)
	assert.False(t, synced)
}

// TestNodeQuoteSource_ClockSyncedFailsWhenNoEndpointAnswers asserts a
// refused or unreachable node yields a typed error, so the collector records
// the clock as unknown instead of as wrong.
func TestNodeQuoteSource_ClockSyncedFailsWhenNoEndpointAnswers(t *testing.T) {
	pki := newTestPKI(t, "node-01.example.internal")
	node := newFakeNode(t, pki)
	node.respondClock = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
	}
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{eps: []Endpoint{{Address: node.address(), ServerName: "node-01.example.internal", Source: SourcePlatformDNS}}},
		TLS:       dialerWith(pki, pki.client),
	})
	require.NoError(t, err)

	_, err = src.ClockSynced(context.Background(), "42")
	var unavailable ErrClockStateUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "42", unavailable.DeviceID)
	assert.NotEmpty(t, unavailable.Attempts, "the error names what was tried")
	assert.Contains(t, unavailable.Error(), "reported clock state")
}

// TestNodeQuoteSource_ClockSyncedPropagatesResolverFailure asserts a device
// with no dialable address fails before any request.
func TestNodeQuoteSource_ClockSyncedPropagatesResolverFailure(t *testing.T) {
	src, err := NewNodeQuoteSource(NodeQuoteSourceConfig{
		Addresses: &fixedResolver{err: ErrNoAddressResolver{}},
		TLS:       func(context.Context, Endpoint) (*tls.Config, error) { return nil, nil },
	})
	require.NoError(t, err)

	_, err = src.ClockSynced(context.Background(), "42")
	var noResolver ErrNoAddressResolver
	require.ErrorAs(t, err, &noResolver)
}

// syncedClock answers a fixed state.
type syncedClock struct {
	synced bool
	err    error
}

func (c *syncedClock) ClockSynced(context.Context, string) (bool, error) {
	return c.synced, c.err
}

// TestCollectorRecordsClockState asserts the three states reach the report
// distinctly: synced, unsynced, and unknown when no clock source is wired or
// the read failed.
func TestCollectorRecordsClockState(t *testing.T) {
	for name, tc := range map[string]struct {
		clock ClockSource
		want  *bool
	}{
		"no clock source leaves the state unknown": {clock: nil, want: nil},
		"a synced node records true":               {clock: &syncedClock{synced: true}, want: boolPtr(true)},
		"an unsynced node records false":           {clock: &syncedClock{synced: false}, want: boolPtr(false)},
		"a failed read records unknown, never unsynced": {
			clock: &syncedClock{err: ErrClockStateUnavailable{DeviceID: "dev-1"}}, want: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
			c := testCollector(t, Config{Source: newCountingSource(), Clock: tc.clock}, clk)

			report, err := c.collectOnce(context.Background(), "dev-1")
			require.NoError(t, err)
			if tc.want == nil {
				assert.Nil(t, report.TimeSynced)
				return
			}
			require.NotNil(t, report.TimeSynced)
			assert.Equal(t, *tc.want, *report.TimeSynced)
		})
	}
}

// TestCollectorClockStateReachesTheView asserts the state survives the whole
// path a consumer sees: collection, cache, and the rendered view every
// transport serialises.
func TestCollectorClockStateReachesTheView(t *testing.T) {
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	c := testCollector(t, Config{
		Source: newCountingSource(),
		Clock:  &syncedClock{synced: false},
	}, clk)

	c.Collect(context.Background(), "dev-1")

	view, ok := c.Cache().View("dev-1")
	require.True(t, ok)
	require.NotNil(t, view.TimeSynced)
	assert.False(t, *view.TimeSynced, "an unsynced node is visible where the verdict is")
}

func boolPtr(b bool) *bool { return &b }
