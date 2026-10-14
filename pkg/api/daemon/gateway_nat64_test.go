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

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeGatewayNAT64 answers with a scripted health snapshot or error.
type fakeGatewayNAT64 struct {
	health nat64.Health
	err    error
}

func (f *fakeGatewayNAT64) NAT64Status(context.Context) (nat64.Health, error) {
	if f.err != nil {
		return nat64.Health{}, f.err
	}
	return f.health, nil
}

// nat64TestHealth is a fully populated snapshot, so a field the conversion
// forgets shows up as a zero value rather than passing unnoticed.
func nat64TestHealth() nat64.Health {
	return nat64.Health{
		Active:          true,
		InstancePresent: true,
		Prefix:          "64:ff9b::/96",
		Instance:        "tp-nat64",
		Sessions:        42,
		Pool4Used:       17,
		ModuleVersion:   "4.1.14",
		FlowCount:       4,
		LastReconcile:   time.Unix(1700000000, 0),
	}
}

func TestGetNAT64Status_CarriesEveryFieldOntoTheWire(t *testing.T) {
	svc := NewGatewayService(WithNAT64(&fakeGatewayNAT64{health: nat64TestHealth()}))

	resp, err := svc.GetNAT64Status(context.Background(), &platformv1.GetNAT64StatusRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.Status)

	s := resp.Status
	assert.True(t, s.Active)
	assert.True(t, s.InstancePresent)
	assert.Equal(t, "64:ff9b::/96", s.Prefix)
	assert.Equal(t, "tp-nat64", s.Instance)
	assert.Equal(t, uint64(42), s.Sessions)
	assert.Equal(t, uint64(17), s.Pool4Used)
	assert.Equal(t, "4.1.14", s.ModuleVersion)
	assert.Equal(t, uint32(4), s.FlowCount)
	require.NotNil(t, s.LastReconcile)
	assert.Equal(t, int64(1700000000), s.LastReconcile.Seconds)
	assert.Empty(t, s.LastError)
}

func TestGetNAT64Status_ReportsAnInstanceThatHasGone(t *testing.T) {
	// The whole point of deriving health from the kernel: a started service
	// whose instance disappeared must say so on the wire.
	health := nat64TestHealth()
	health.InstancePresent = false
	health.LastError = errors.New("instance vanished")
	svc := NewGatewayService(WithNAT64(&fakeGatewayNAT64{health: health}))

	resp, err := svc.GetNAT64Status(context.Background(), &platformv1.GetNAT64StatusRequest{})
	require.NoError(t, err)
	assert.True(t, resp.Status.Active, "the service is still started")
	assert.False(t, resp.Status.InstancePresent)
	assert.Equal(t, "instance vanished", resp.Status.LastError)
}

func TestGetNAT64Status_OmitsAReconcileThatNeverHappened(t *testing.T) {
	health := nat64TestHealth()
	health.LastReconcile = time.Time{}
	svc := NewGatewayService(WithNAT64(&fakeGatewayNAT64{health: health}))

	resp, err := svc.GetNAT64Status(context.Background(), &platformv1.GetNAT64StatusRequest{})
	require.NoError(t, err)
	assert.Nil(t, resp.Status.LastReconcile,
		"a zero time must not travel as the unix epoch")
}

func TestGetNAT64Status_RefusesWhenNoTranslatorIsWired(t *testing.T) {
	svc := NewGatewayService()

	_, err := svc.GetNAT64Status(context.Background(), &platformv1.GetNAT64StatusRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestNAT64ErrToGRPC_MapsEachFailureToWhatACallerShouldDo(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			// Retryable: the section may be starting, or refused and
			// fixable in configuration.
			"the service is not running",
			&gateway.ErrServiceNotActive{Service: "nat64"},
			codes.Unavailable,
		},
		{
			"the service was never started",
			nat64.ErrNotStarted,
			codes.Unavailable,
		},
		{
			// Not retryable without operator action on the host.
			"the kernel cannot carry the translator",
			&nat64.ErrNAT64ModuleUnavailable{Instance: "tp-nat64", Err: errors.New("module not found")},
			codes.FailedPrecondition,
		},
		{
			"anything else",
			errors.New("boom"),
			codes.Internal,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, status.Code(nat64ErrToGRPC(tc.err)))
		})
	}
	assert.NoError(t, nat64ErrToGRPC(nil))
}

func TestGetNAT64Status_SurfacesTheBackendFailure(t *testing.T) {
	svc := NewGatewayService(WithNAT64(&fakeGatewayNAT64{
		err: &nat64.ErrNAT64ModuleUnavailable{Instance: "tp-nat64", Err: errors.New("module not found")},
	}))

	_, err := svc.GetNAT64Status(context.Background(), &platformv1.GetNAT64StatusRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, err.Error(), "module not found",
		"the operator needs the kernel's own reason, not just a code")
}

func TestSetNAT64_WiresTheBackendAfterConstruction(t *testing.T) {
	svc := NewGatewayService()
	assert.Nil(t, svc.NAT64())

	backend := &fakeGatewayNAT64{health: nat64TestHealth()}
	svc.SetNAT64(backend)
	assert.NotNil(t, svc.NAT64())

	resp, err := svc.GetNAT64Status(context.Background(), &platformv1.GetNAT64StatusRequest{})
	require.NoError(t, err)
	assert.True(t, resp.Status.Active)
}

// TestNAT64QUICAdapter_ReportsTheSameSnapshot: the QUIC adapter and the
// gRPC service must not drift in what they report, so the same health
// snapshot is asserted through both.
func TestNAT64QUICAdapter_ReportsTheSameSnapshot(t *testing.T) {
	adapter := &fullGatewayQUICAdapter{}
	adapter.SetNAT64(&fakeGatewayNAT64{health: nat64TestHealth()})

	info, err := adapter.NAT64Status(context.Background())
	require.NoError(t, err)
	assert.True(t, info.Active)
	assert.True(t, info.InstancePresent)
	assert.Equal(t, "64:ff9b::/96", info.Prefix)
	assert.Equal(t, "tp-nat64", info.Instance)
	assert.Equal(t, uint64(42), info.Sessions)
	assert.Equal(t, uint64(17), info.Pool4Used)
	assert.Equal(t, "4.1.14", info.ModuleVersion)
	assert.Equal(t, 4, info.FlowCount)
	assert.Equal(t, int64(1700000000), info.LastReconcile)
}

func TestNAT64QUICAdapter_RefusesWhenUnwired(t *testing.T) {
	adapter := &fullGatewayQUICAdapter{}
	_, err := adapter.NAT64Status(context.Background())
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
}

func TestNAT64QUICAdapter_ZoneOnlyAdapterReportsNotConfigured(t *testing.T) {
	// A daemon with zone services but no gateway controller must say "not
	// configured", not return a zero snapshot that reads as a healthy
	// translator holding no sessions.
	adapter := &zoneGatewayAdapter{}
	_, err := adapter.NAT64Status(context.Background())
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
}

func TestNAT64RESTAdapter_ReportsTheSameSnapshot(t *testing.T) {
	svc := &gatewayRESTService{nat64: &fakeGatewayNAT64{health: nat64TestHealth()}}

	out, err := svc.GetNAT64Status(context.Background())
	require.NoError(t, err)
	assert.True(t, out.Active)
	assert.Equal(t, "64:ff9b::/96", out.Prefix)
	assert.Equal(t, uint64(42), out.Sessions)
	assert.Equal(t, 4, out.FlowCount)
	assert.Equal(t, time.Unix(1700000000, 0), out.LastReconcile)
}

func TestNAT64RESTAdapter_RefusesWhenUnwired(t *testing.T) {
	svc := &gatewayRESTService{}
	_, err := svc.GetNAT64Status(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

func TestNAT64MCPProviders_RefuseWhenUnwired(t *testing.T) {
	_, err := (&MCPServiceProvider{}).GatewayNAT64Status(context.Background())
	require.Error(t, err)
}

// TestNAT64ErrorMapping_EveryTransportAgrees: the same translator failure
// reaches REST and QUIC with the meaning gRPC gives it. Before the #661
// review a kernel without the module fell through to a 500 on REST and
// StatusInternalError on QUIC, while gRPC said FailedPrecondition.
func TestNAT64ErrorMapping_EveryTransportAgrees(t *testing.T) {
	moduleErr := &nat64.ErrNAT64ModuleUnavailable{Instance: "tp-nat64", Err: errors.New("module not found")}

	t.Run("REST", func(t *testing.T) {
		var unavailable rest.ErrNAT64ModuleUnavailable
		require.ErrorAs(t, mapNAT64Error(moduleErr), &unavailable)
		assert.Contains(t, unavailable.Detail, "module not found")
		assert.Equal(t, rest.ErrNAT64NotConfigured{}, mapNAT64Error(nat64.ErrNotStarted))
		assert.Equal(t, rest.ErrNAT64NotConfigured{}, mapNAT64Error(&gateway.ErrServiceNotActive{Service: "nat64"}))
		boom := errors.New("boom")
		assert.Equal(t, boom, mapNAT64Error(boom))
		assert.NoError(t, mapNAT64Error(nil))
	})

	t.Run("QUIC", func(t *testing.T) {
		err := mapNAT64ToQUICError(moduleErr)
		assert.ErrorIs(t, err, quic.ErrGatewayPreconditionFailed)
		assert.Contains(t, err.Error(), "module not found")
		assert.ErrorIs(t, mapNAT64ToQUICError(nat64.ErrNotStarted), errGatewayFeatureNotConfigured)
		assert.ErrorIs(t, mapNAT64ToQUICError(&gateway.ErrServiceNotActive{Service: "nat64"}), errGatewayFeatureNotConfigured)
		boom := errors.New("boom")
		assert.Equal(t, boom, mapNAT64ToQUICError(boom))
		assert.NoError(t, mapNAT64ToQUICError(nil))
	})

	t.Run("QUIC adapter", func(t *testing.T) {
		adapter := &fullGatewayQUICAdapter{}
		adapter.SetNAT64(&fakeGatewayNAT64{err: moduleErr})
		_, err := adapter.NAT64Status(context.Background())
		assert.ErrorIs(t, err, quic.ErrGatewayPreconditionFailed)
	})

	t.Run("REST adapter", func(t *testing.T) {
		svc := &gatewayRESTService{nat64: &fakeGatewayNAT64{err: moduleErr}}
		_, err := svc.GetNAT64Status(context.Background())
		var unavailable rest.ErrNAT64ModuleUnavailable
		assert.ErrorAs(t, err, &unavailable)
	})
}
