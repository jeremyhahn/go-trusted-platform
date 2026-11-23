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

package netplan_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// TestPlatformHost derives a host's platform-VRF address from the
// platform-hosts range (10.4.144.0/20 in environment 4).
func TestPlatformHost(t *testing.T) {
	p := referencePlan(t)

	a, err := p.PlatformHost(1)
	require.NoError(t, err)
	assert.Equal(t, "10.4.144.1", a.String())

	a, err = p.PlatformHost(4094)
	require.NoError(t, err)
	assert.Equal(t, "10.4.159.254", a.String())

	for _, n := range []uint32{0, 4095} {
		_, err := p.PlatformHost(n)
		require.Error(t, err, "host %d", n)
		var target netplan.ErrHostNumber
		require.True(t, errors.As(err, &target), "host %d", n)
		assert.Equal(t, n, target.Host)
	}
}

// TestPlatformHostNumber reverses PlatformHost.
func TestPlatformHostNumber(t *testing.T) {
	p := referencePlan(t)

	n, ok := p.PlatformHostNumber(netip.MustParseAddr("10.4.144.1"))
	assert.True(t, ok)
	assert.Equal(t, uint32(1), n)

	n, ok = p.PlatformHostNumber(netip.MustParseAddr("10.4.159.254"))
	assert.True(t, ok)
	assert.Equal(t, uint32(4094), n)

	for _, s := range []string{"10.4.144.0", "10.4.159.255", "10.4.160.1", "fd12:3456:789a:ffff::1"} {
		n, ok := p.PlatformHostNumber(netip.MustParseAddr(s))
		assert.False(t, ok, s)
		assert.Equal(t, uint32(0), n, s)
	}
}
