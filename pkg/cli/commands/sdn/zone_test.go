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
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestZoneCommand_Subcommands lists the zone verbs; assign is gone because
// networks are zones.
func TestZoneCommand_Subcommands(t *testing.T) {
	cmd := NewZoneCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	var got []string
	for _, c := range cmd.Commands() {
		got = append(got, c.Name())
	}
	assert.ElementsMatch(t, []string{"list", "create", "update", "delete"}, got)
}

// TestZoneFlags_Config parses every zone flag into the proto config.
func TestZoneFlags_Config(t *testing.T) {
	var f zoneFlags
	cmd := &cobra.Command{Use: "create"}
	f.register(cmd, "Zone name")
	require.NoError(t, cmd.ParseFlags([]string{
		"--name", "lab", "--offset", "9",
		"--port-class", "hypervisor", "--port-class", "gateway",
		"--isolate-from", "storage",
		"--allow-to", "control-plane:dns,acme", "--allow-to", "backup",
		"--service", "ssh", "--isolate",
		"--reason", "lab resolver", "--approved-by", "owner",
	}))

	cfg, err := f.config()
	require.NoError(t, err)
	assert.Equal(t, "lab", cfg.GetName())
	assert.Equal(t, uint32(9), cfg.GetOffset())
	assert.Equal(t, []string{"hypervisor", "gateway"}, cfg.GetPortClasses())
	assert.Equal(t, []string{"storage"}, cfg.GetIsolateFrom())
	require.Len(t, cfg.GetAllowTo(), 2)
	assert.Equal(t, "control-plane", cfg.GetAllowTo()[0].GetZone())
	assert.Equal(t, []string{"dns", "acme"}, cfg.GetAllowTo()[0].GetServices())
	assert.Equal(t, "backup", cfg.GetAllowTo()[1].GetZone())
	assert.Empty(t, cfg.GetAllowTo()[1].GetServices())
	assert.Equal(t, []string{"ssh"}, cfg.GetServices())
	assert.True(t, cfg.GetIsolate())
	assert.Equal(t, "owner", cfg.GetPrivilegedAccess().GetApprovedBy())
}

// TestZoneFlags_ConfigErrors refuses malformed --allow-to values and a
// half-set privileged_access.
func TestZoneFlags_ConfigErrors(t *testing.T) {
	for _, v := range []string{"", ":dns", "control-plane:", "control-plane:dns,"} {
		_, err := (&zoneFlags{name: "lab", allowTo: []string{v}}).config()
		var target *ErrInvalidAllowTo
		require.True(t, errors.As(err, &target), "value %q: got %v", v, err)
		assert.Contains(t, target.Error(), "--allow-to")
	}

	_, err := (&zoneFlags{name: "lab", reason: "x"}).config()
	var pa *ErrIncompletePrivilegedAccess
	require.True(t, errors.As(err, &pa))
	_, err = (&zoneFlags{name: "lab", approvedBy: "owner"}).config()
	require.True(t, errors.As(err, &pa))
	assert.Contains(t, pa.Error(), "--approved-by")
}

// TestZoneCreate_RefusesBadFlagsBeforeConnecting returns the flag error
// without dialing the daemon.
func TestZoneCreate_RefusesBadFlagsBeforeConnecting(t *testing.T) {
	err := runZoneCreate(&cli.CommonFlags{}, &zoneFlags{name: "lab", allowTo: []string{":x"}})
	var target *ErrInvalidAllowTo
	require.True(t, errors.As(err, &target), "got %v", err)

	err = runZoneUpdate(&cli.CommonFlags{}, &zoneFlags{name: "lab", reason: "x"})
	var pa *ErrIncompletePrivilegedAccess
	require.True(t, errors.As(err, &pa), "got %v", err)
}

// TestRunZone_NoContext reaches the daemon connection on every zone verb
// once the flags are valid; without a context it fails with
// ErrNoContextSet. The RPC itself is exercised by the integration suite.
func TestRunZone_NoContext(t *testing.T) {
	assertNoContextError(t, runZoneList(noContextFlags(), "provisioning"))
	assertNoContextError(t, runZoneCreate(noContextFlags(), &zoneFlags{name: "lab", offset: 9}))
	assertNoContextError(t, runZoneUpdate(noContextFlags(), &zoneFlags{name: "storage", isolate: true}))
	assertNoContextError(t, runZoneDelete(noContextFlags(), "lab"))
}
