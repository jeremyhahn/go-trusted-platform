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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
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
	var (
		bundlePath           string
		installToSystemTrust bool
		certPath             string
	)
	cmd := &cobra.Command{
		Use:   "direct",
		Short: "Direct CA bundle copy (operator-supplied trust root)",
		Long: `Bootstrap trust from a CA bundle PEM file supplied out of band. The
command decodes every PEM block in the file and requires at least one
CERTIFICATE block that parses as an X.509 CA certificate. With
--install-to-system-trust it writes the bundle to --cert-path; run the OS
trust-store update command (e.g. update-ca-certificates) afterwards.

Example:
  platformctl bootstrap direct --bundle /path/to/ca.pem
  platformctl bootstrap direct --bundle /path/to/ca.pem --install-to-system-trust`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bundlePath == "" {
				return &MessageError{Msg: "bootstrap direct: --bundle is required"}
			}
			info, err := os.Stat(bundlePath)
			if err != nil {
				return &WrappedError{Msg: "bootstrap direct: cannot stat bundle", Err: err}
			}
			if info.IsDir() {
				return &MessageError{Msg: fmt.Sprintf("bootstrap direct: %s is a directory", bundlePath)}
			}
			bundle, err := os.ReadFile(bundlePath)
			if err != nil {
				return ErrFileReadFailed{Path: bundlePath, Err: err}
			}
			caCount, err := validateDirectBundle(bundlePath, bundle)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Direct CA bundle accepted: %s (%d bytes, %d CA certificates)\n",
				bundlePath, len(bundle), caCount)
			if installToSystemTrust {
				if err := trust.InstallToSystemTrust(bundle, certPath); err != nil {
					return ErrTrustInstallFailed{Path: certPath, Cause: err}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "CA bundle installed to %s\n", certPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to the CA bundle PEM file")
	cmd.Flags().BoolVar(&installToSystemTrust, "install-to-system-trust", false, "install the CA bundle into the system trust store")
	cmd.Flags().StringVar(&certPath, "cert-path", defaultCertPath, "system trust store certificate path")
	return cmd
}

// validateDirectBundle decodes every PEM block in bundle, parses each
// CERTIFICATE block and returns the number of CA certificates found. It
// fails when the bundle holds no PEM block, a CERTIFICATE block does not
// parse, or no certificate is a CA.
func validateDirectBundle(path string, bundle []byte) (int, error) {
	var blocks, caCount int
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, ErrDirectBundleInvalidCert{Path: path, Cause: err}
		}
		if cert.IsCA {
			caCount++
		}
	}
	if blocks == 0 {
		return 0, ErrDirectBundleNotPEM{Path: path}
	}
	if caCount == 0 {
		return 0, ErrDirectBundleNoCA{Path: path}
	}
	return caCount, nil
}
