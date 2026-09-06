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

package commands

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
)

// stubClockStatus stands in for the running time service.
type stubClockStatus struct {
	status *ntp.Status
	err    error
}

func (s *stubClockStatus) Status(context.Context) (*ntp.Status, error) {
	return s.status, s.err
}

// TestNTPClockAdapter_ProjectsTheStatus asserts the adapter carries the
// fields the attestation clock route serves, and that a synchronized node
// answers a present true rather than an absent value.
func TestNTPClockAdapter_ProjectsTheStatus(t *testing.T) {
	adapter := newNTPClockAdapter(&stubClockStatus{status: &ntp.Status{
		Synced:           true,
		Stratum:          3,
		LeapStatus:       "Normal",
		OffsetSeconds:    -0.000012,
		SourcesReachable: 1,
		SourcesTotal:     2,
	}})
	require.NotNil(t, adapter)

	state, err := adapter.ClockState(context.Background())
	require.NoError(t, err)
	require.NotNil(t, state.Synced)
	assert.True(t, *state.Synced)
	assert.EqualValues(t, 3, state.Stratum)
	assert.Equal(t, "Normal", state.LeapStatus)
	assert.EqualValues(t, 1, state.SourcesReachable)
	assert.EqualValues(t, 2, state.SourcesTotal)
}

// TestNTPClockAdapter_UnsyncedNodeSaysSo asserts an undisciplined clock is
// reported as a present false, with the daemon's own words for why.
func TestNTPClockAdapter_UnsyncedNodeSaysSo(t *testing.T) {
	adapter := newNTPClockAdapter(&stubClockStatus{status: &ntp.Status{
		Synced:        false,
		LeapStatus:    "Not synchronised",
		Anomaly:       true,
		AnomalyReason: "correction of 42s after convergence",
	}})
	state, err := adapter.ClockState(context.Background())
	require.NoError(t, err)
	require.NotNil(t, state.Synced)
	assert.False(t, *state.Synced)
	assert.True(t, state.Anomaly)
	assert.Contains(t, state.AnomalyReason, "42s")
}

// TestNTPClockAdapter_ErrorsAreNotVerdicts asserts a failed read surfaces as
// an error. Anything else would let a control-socket failure be recorded as
// a wrong clock on the node.
func TestNTPClockAdapter_ErrorsAreNotVerdicts(t *testing.T) {
	t.Run("service error", func(t *testing.T) {
		adapter := newNTPClockAdapter(&stubClockStatus{err: errors.New("control socket unreachable")})
		state, err := adapter.ClockState(context.Background())
		require.Error(t, err)
		assert.Nil(t, state.Synced)
	})

	t.Run("no status and no error", func(t *testing.T) {
		adapter := newNTPClockAdapter(&stubClockStatus{})
		_, err := adapter.ClockState(context.Background())
		var empty ErrClockStatusEmpty
		require.ErrorAs(t, err, &empty)
		assert.Contains(t, empty.Error(), "no status")
	})
}

// TestNTPClockAdapter_NilServiceYieldsNoReader asserts a node with no time
// service produces an untyped nil, so the route answers "not configured"
// instead of panicking on the first request.
func TestNTPClockAdapter_NilServiceYieldsNoReader(t *testing.T) {
	assert.Nil(t, newNTPClockAdapter(nil))
}

// TestNodeClockStatusReader asserts the wiring hands over the running time
// service, and hands over nothing when there is none — including for a nil
// App, which is how a node with no platform context is wired.
func TestNodeClockStatusReader(t *testing.T) {
	assert.Nil(t, nodeClockStatusReader(nil), "a nil app has no time service")
	assert.Nil(t, nodeClockStatusReader(&app.App{}), "an app with no NTP service has none")
	assert.Nil(t, newNTPClockAdapter(nodeClockStatusReader(&app.App{})),
		"the untyped nil must survive into the adapter")
}
