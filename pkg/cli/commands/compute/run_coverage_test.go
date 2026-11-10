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

package compute

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestCommandRunE_NoContext drives each command's RunE closure into its run
// function and asserts the missing CLI context surfaces as ErrNoContextSet.
func TestCommandRunE_NoContext(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatTable}
	}

	cases := []struct {
		name  string
		cmd   *cobra.Command
		args  []string
		flags map[string]string
	}{
		{name: "create", cmd: newCreateCommand(getFlags), flags: map[string]string{"name": "test-vm"}},
		{name: "start", cmd: newStartCommand(getFlags), args: []string{"test-vm"}},
		{name: "stop", cmd: newStopCommand(getFlags), args: []string{"test-vm"}},
		{name: "delete", cmd: newDeleteCommand(getFlags), args: []string{"test-vm"}},
		{name: "get", cmd: newGetCommand(getFlags), args: []string{"test-vm"}},
		{name: "list", cmd: newListCommand(getFlags)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cmd.RunE == nil {
				t.Fatalf("%s command should have RunE set", tc.name)
			}
			for k, v := range tc.flags {
				if err := tc.cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set --%s: %v", k, err)
				}
			}
			err := tc.cmd.RunE(tc.cmd, tc.args)
			if !errors.As(err, new(cli.ErrNoContextSet)) {
				t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
			}
		})
	}
}
