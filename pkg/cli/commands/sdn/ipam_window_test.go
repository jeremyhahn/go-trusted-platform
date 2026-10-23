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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestIPAMWindowFlags_Parse checks the window flags parse into the struct
// and changed() reports that one was given.
func TestIPAMWindowFlags_Parse(t *testing.T) {
	var w ipamWindowFlags
	cmd := &cobra.Command{Use: "x"}
	w.register(cmd)
	require.NoError(t, cmd.ParseFlags([]string{
		"--reserved", "192.0.2.1/32,192.0.2.8/30", "--range-start", "192.0.2.50", "--range-end", "192.0.2.254",
	}))
	assert.Equal(t, []string{"192.0.2.1/32", "192.0.2.8/30"}, w.reserved)
	assert.Equal(t, "192.0.2.50", w.rangeStart)
	assert.Equal(t, "192.0.2.254", w.rangeEnd)
	assert.True(t, w.changed(cmd))
}

// TestIPAMWindowFlags_Unchanged reports no change without window flags, and
// refuses a malformed flag value.
func TestIPAMWindowFlags_Unchanged(t *testing.T) {
	var w ipamWindowFlags
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().String("name", "", "")
	w.register(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--name", "renamed"}))
	assert.False(t, w.changed(cmd))
	assert.Error(t, cmd.ParseFlags([]string{"--range-start"}), "a flag without its value is refused")
}

// TestIPAMPoolCommands_RegisterWindowFlags checks create and update expose
// the window flags.
func TestIPAMPoolCommands_RegisterWindowFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }
	for _, cmd := range []*cobra.Command{newIPAMPoolCreateCommand(getFlags), newIPAMPoolUpdateCommand(getFlags)} {
		for _, f := range []string{"reserved", "range-start", "range-end"} {
			assert.NotNil(t, cmd.Flags().Lookup(f), "%s --%s", cmd.Use, f)
		}
	}
}

// parsedPoolUpdate parses args into the update command's flags.
func parsedPoolUpdate(t *testing.T, args ...string) (*ipamPoolUpdateFlags, *cobra.Command) {
	t.Helper()
	var opts ipamPoolUpdateFlags
	cmd := &cobra.Command{Use: "update"}
	cmd.Flags().StringVar(&opts.poolID, "id", "", "")
	cmd.Flags().StringVar(&opts.name, "name", "", "")
	cmd.Flags().StringVar(&opts.zone, "zone", "", "")
	cmd.Flags().StringVar(&opts.description, "description", "", "")
	cmd.Flags().Int64Var(&opts.leaseSecs, "lease-seconds", 0, "")
	opts.window.register(cmd)
	require.NoError(t, cmd.ParseFlags(args))
	return &opts, cmd
}

var currentPool = &platformv1.IPAMPool{Id: "pool-1", Zone: "lab", Description: "lab pool"}

// TestIPAMPoolUpdateFlags_KeepsUnpassedFields: flags that were not passed
// carry the pool's current zone and description and leave both durations
// alone, since UpdateIPAMPool would otherwise clear them.
func TestIPAMPoolUpdateFlags_KeepsUnpassedFields(t *testing.T) {
	opts, cmd := parsedPoolUpdate(t, "--id", "pool-1", "--name", "renamed")

	req := opts.request(cmd, currentPool)

	assert.Equal(t, "renamed", req.GetName())
	assert.Equal(t, "lab", req.GetZone())
	assert.Equal(t, "lab pool", req.GetDescription())
	assert.Equal(t, keepDuration, req.GetDefaultLeaseDurationNanos())
	assert.Equal(t, keepDuration, req.GetInactivityTimeoutNanos())
	assert.False(t, req.GetUpdateWindow())
}

// TestIPAMPoolUpdateFlags_PassedFieldsReplace: passed flags win, including
// an explicit empty zone and a zero lease.
func TestIPAMPoolUpdateFlags_PassedFieldsReplace(t *testing.T) {
	opts, cmd := parsedPoolUpdate(t, "--id", "pool-1", "--zone", "", "--description", "dmz pool", "--lease-seconds", "0")

	req := opts.request(cmd, currentPool)

	assert.Empty(t, req.GetZone())
	assert.Equal(t, "dmz pool", req.GetDescription())
	assert.Zero(t, req.GetDefaultLeaseDurationNanos())
	assert.Equal(t, keepDuration, req.GetInactivityTimeoutNanos())
}

func TestRunIPAMPoolUpdate_NoContext(t *testing.T) {
	built := false
	err := runIPAMPoolUpdate(noContextFlags(), "pool-1", func(*platformv1.IPAMPool) *platformv1.UpdateIPAMPoolRequest {
		built = true
		return &platformv1.UpdateIPAMPoolRequest{}
	})
	assertNoContextError(t, err)
	assert.False(t, built, "no update is built without the current pool")
}
