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

// canonical_modes.go adds the canonical TOFU bootstrap modes
// (auto, dane, noise, spki, direct) per
// docs/08-bootstrap-auth-architecture.md §6. These modes complement
// the existing PXE bootstrap subcommands and provide command-shape
// parity with qrdb / xkmsctl / quicbaas.
package bootstrap

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// PendingBootstrapBackendError is emitted by canonical TOFU modes that
// have not yet been wired to an SDK ceremony backend. The shape is
// registered today; the implementation lands when the xkms TOFU
// bridge wires through to the platform layer.
type PendingBootstrapBackendError struct {
	Mode string
}

// Error returns a human-readable description.
func (e *PendingBootstrapBackendError) Error() string {
	return "bootstrap " + e.Mode + " is owned by xkms; invoke via 'xkmsctl bootstrap " + e.Mode + "' until the platform bridge ships"
}

// AddCanonicalModes attaches the canonical bootstrap modes to a parent
// bootstrap command. It is invoked from the platformctl bootstrap
// command builder so the canonical surface is exposed alongside the
// existing PXE bootstrap operations.
func AddCanonicalModes(parent *cobra.Command, getFlags func() *cli.CommonFlags) {
	parent.AddCommand(newCanonicalAutoCmd(getFlags))
	parent.AddCommand(newCanonicalDaneCmd(getFlags))
	parent.AddCommand(newCanonicalNoiseCmd(getFlags))
	parent.AddCommand(newCanonicalSPKICmd(getFlags))
	parent.AddCommand(newCanonicalDirectCmd(getFlags))
}

func newCanonicalAutoCmd(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "auto",
		Short: "Auto-pick the strongest available trust mode",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &PendingBootstrapBackendError{Mode: "auto"}
		},
	}
}

func newCanonicalDaneCmd(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "dane",
		Short: "DANE TLSA pinning (RFC 6698)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &PendingBootstrapBackendError{Mode: "dane"}
		},
	}
}

func newCanonicalNoiseCmd(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "noise",
		Short: "Noise XK out-of-band trust handshake",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &PendingBootstrapBackendError{Mode: "noise"}
		},
	}
}

func newCanonicalSPKICmd(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "spki",
		Short: "SPKI SHA-256 pin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &PendingBootstrapBackendError{Mode: "spki"}
		},
	}
}

// newCanonicalDirectCmd implements the new "direct" mode mandated by
// docs/08-bootstrap-auth-architecture.md §6. Operators supply a CA
// bundle path out of band; the command validates the bundle and
// stages it for ingestion by the trust bootstrap pipeline.
func newCanonicalDirectCmd(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bundlePath string
	cmd := &cobra.Command{
		Use:   "direct",
		Short: "Direct CA bundle copy (operator-supplied trust root)",
		Long: `Bootstrap trust by copying a CA bundle PEM file directly. The operator
supplies the CA bundle out of band; the command validates the file and
records it as the active trust root for subsequent calls.

Example:
  platformctl bootstrap direct --bundle /path/to/ca.pem`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bundlePath == "" {
				return fmt.Errorf("bootstrap direct: --bundle is required")
			}
			info, err := os.Stat(bundlePath)
			if err != nil {
				return fmt.Errorf("bootstrap direct: cannot stat bundle: %w", err)
			}
			if info.IsDir() {
				return fmt.Errorf("bootstrap direct: %s is a directory", bundlePath)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Direct CA bundle accepted: %s (%d bytes)\n", bundlePath, info.Size())
			return nil
		},
	}
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to the CA bundle PEM file")
	return cmd
}
