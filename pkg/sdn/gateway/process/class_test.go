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
