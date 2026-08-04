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
	"context"
	"fmt"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrAlgorithmsFailed is returned when listing supported algorithms fails
type ErrAlgorithmsFailed struct {
	Err error
}

func (e ErrAlgorithmsFailed) Error() string {
	return fmt.Sprintf("failed to list supported algorithms: %v", e.Err)
}

func (e ErrAlgorithmsFailed) Unwrap() error {
	return e.Err
}

// keyAlgorithmsOutput is the CLI presentation of the supported algorithms.
type keyAlgorithmsOutput struct {
	Algorithms []string `json:"algorithms"`
}

// newKeyAlgorithmsCommand creates the key algorithms subcommand
func newKeyAlgorithmsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "algorithms",
		Short: "List supported algorithms",
		Long: `Display the list of cryptographic algorithms supported by the current KMS backend.

Different backends may support different algorithms. Use this command to check
which algorithms are available before generating or importing keys.

Examples:
  # List supported algorithms
  platformctl kms key algorithms

  # Output as JSON
  platformctl kms key algorithms --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyAlgorithms(getFlags())
		},
	}

	return cmd
}

// runKeyAlgorithms opens the SDK connection and delegates to executeKeyAlgorithms.
func runKeyAlgorithms(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyAlgorithms(base.Context(), client, base.Printer())
}

// executeKeyAlgorithms lists the supported algorithms via the quicbaas
// SDK KMS client.
func executeKeyAlgorithms(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer) error {
	resp, err := client.GetSupportedAlgorithms(ctx)
	if err != nil {
		return ErrAlgorithmsFailed{Err: err}
	}
	return printer.Print(&keyAlgorithmsOutput{Algorithms: resp.Algorithms})
}
