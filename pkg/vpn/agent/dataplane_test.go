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

package agent

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

func TestLeaseAddress_ParsesThePrefixTheLeaseAssigns(t *testing.T) {
	address, err := leaseAddress(gwvpn.DataPlaneMASQUE, &gwvpn.LeaseWire{Address: "fd00:8::2/128"})

	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("fd00:8::2/128"), address)

	_, err = leaseAddress(gwvpn.DataPlaneMASQUE, &gwvpn.LeaseWire{Address: "10.8.0.2"})
	var unusable *ErrLeaseUnusable
	require.ErrorAs(t, err, &unusable)
	assert.Equal(t, gwvpn.DataPlaneMASQUE, unusable.Kind)
}

func TestLeaseRoutes_MasksEachPrefixAndRefusesNone(t *testing.T) {
	routes, err := leaseRoutes(gwvpn.DataPlaneMASQUE, []string{"10.20.1.1/16", "fd00:20::/48"})

	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:20::/48")}, routes)

	var unusable *ErrLeaseUnusable
	_, err = leaseRoutes(gwvpn.DataPlaneMASQUE, nil)
	require.ErrorAs(t, err, &unusable)
	assert.Equal(t, "the lease routes nothing", unusable.Reason)
	_, err = leaseRoutes(gwvpn.DataPlaneMASQUE, []string{"zone-b"})
	require.ErrorAs(t, err, &unusable)
	assert.Error(t, unusable.Cause)
}

func TestErrLeaseUnusable_NamesThePlaneAndUnwraps(t *testing.T) {
	cause := &errFake{"parse"}

	assert.Equal(t, "data plane masque: unusable lease: no routes", (&ErrLeaseUnusable{Kind: gwvpn.DataPlaneMASQUE, Reason: "no routes"}).Error())
	err := &ErrLeaseUnusable{Kind: gwvpn.DataPlaneMASQUE, Reason: "address x", Cause: cause}
	assert.Equal(t, "data plane masque: unusable lease: address x: parse failed", err.Error())
	assert.ErrorIs(t, err, cause)
}
