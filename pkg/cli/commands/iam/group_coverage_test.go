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

package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// ErrGroupMembershipNotImplemented
// =============================================================================

func TestErrGroupMembershipNotImplemented(t *testing.T) {
	err := ErrGroupMembershipNotImplemented{}
	assert.Contains(t, err.Error(), "not yet implemented")
}

// =============================================================================
// Group Command Structure Coverage
// =============================================================================

func TestGroupGetCommand_HasRunE(t *testing.T) {
	cmd := newGroupGetCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "get")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestGroupDeleteCommand_HasRunE(t *testing.T) {
	cmd := newGroupDeleteCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "delete")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}

func TestGroupAddMemberCommand_ReturnsNotImplemented(t *testing.T) {
	cmd := newGroupAddMemberCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "add-member")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
	// Execute with the required args
	cmd.SetArgs([]string{"tenant-1", "group-1", "user-1"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.IsType(t, ErrGroupMembershipNotImplemented{}, err)
}

func TestGroupRemoveMemberCommand_ReturnsNotImplemented(t *testing.T) {
	cmd := newGroupRemoveMemberCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Contains(t, cmd.Use, "remove-member")
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
	// Execute with the required args
	cmd.SetArgs([]string{"tenant-1", "group-1", "user-1"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.IsType(t, ErrGroupMembershipNotImplemented{}, err)
}
