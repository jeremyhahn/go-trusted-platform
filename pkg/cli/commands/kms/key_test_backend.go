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

package kms

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrBackendTestNotImplemented is returned when backend test is not yet implemented
type ErrBackendTestNotImplemented struct{}

func (e ErrBackendTestNotImplemented) Error() string {
	return "backend test is not yet implemented in the platform KMS service"
}

// ErrBackendTestFailed is returned when the backend test fails
type ErrBackendTestFailed struct {
	Err error
}

func (e ErrBackendTestFailed) Error() string {
	return fmt.Sprintf("backend test failed: %v", e.Err)
}

// newKeyBackendTestCommand creates the key backend-test subcommand
func newKeyBackendTestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend-test",
		Short: "Test KMS backend functionality (not yet implemented)",
		Long: `Perform a seal/unseal test cycle to verify the KMS backend is functioning correctly.

NOTE: This command is not yet implemented in the platform KMS service.

This command tests the core cryptographic operations of the backend by performing
a complete seal and unseal cycle. Use this to verify backend connectivity and
functionality after configuration changes or to diagnose issues.

Examples:
  platformctl kms key backend-test`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrBackendTestNotImplemented{}
		},
	}

	return cmd
}
