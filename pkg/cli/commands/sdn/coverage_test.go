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

package sdn

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Command Structure Tests (covering Long descriptions and flag registration)
// =============================================================================

func TestBridgeGetCommand_LongDescription(t *testing.T) {
	cmd := newBridgeGetCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "get <bridge-id>", cmd.Use)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)
}

func TestGatewayStatusCommand_LongDescription(t *testing.T) {
	cmd := newGatewayStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "status", cmd.Use)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)
}

func TestOverlayStatusCommand_LongDescription(t *testing.T) {
	cmd := newOverlayStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "status", cmd.Use)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)
}

func TestPolicyGetCommand_LongDescription(t *testing.T) {
	cmd := newPolicyGetCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "get <policy-id>", cmd.Use)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)
}

func TestVLANDeleteCommand_LongDescription(t *testing.T) {
	cmd := newVLANDeleteCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "delete <vlan-id>", cmd.Use)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)
}
