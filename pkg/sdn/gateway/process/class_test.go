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

//go:build linux

package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
)

// TestClassTable_FHRPRunsInTheDatapath: the VRRP speaker opens raw sockets
// (CAP_NET_RAW) and programs the virtual addresses over netlink
// (CAP_NET_ADMIN), which only the datapath process keeps.
func TestClassTable_FHRPRunsInTheDatapath(t *testing.T) {
	def, err := DefinitionForService(gateway.ServiceFHRP)
	require.NoError(t, err)
	assert.Equal(t, "datapath", def.Name)
	assert.Equal(t, ClassKernel, def.Class)
}

// The datapath hosts the FHRP speaker, whose announcer sends the IPv4
// takeover's gratuitous ARP over AF_PACKET; no other process may open it.
func TestClassTable_DatapathOpensAFPacket(t *testing.T) {
	def, err := DefinitionForService(gateway.ServiceFHRP)
	require.NoError(t, err)
	assert.Contains(t, def.AddressFamilies, uint32(unix.AF_PACKET))
	program := seccompProgram(filterTable, def)
	assert.Equal(t, int(seccompAllow), evaluate(t, program, filterTable.arch, filterTable.socket, unix.AF_PACKET),
		"the announcer's AF_PACKET socket is allowed")
	for _, other := range Definitions() {
		if other.Name == def.Name {
			continue
		}
		assert.NotContainsf(t, other.AddressFamilies, uint32(unix.AF_PACKET), "process %q", other.Name)
	}
}
