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

package switchcmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	switchsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/switch"
)

// defaultCLITimeout is the context deadline for all switch CLI operations.
const defaultCLITimeout = 30 * time.Second

// switchFlags holds the common flags for switch CLI commands.
type switchFlags struct {
	serverURL  string
	switchName string
	port       string
	vlan       int
}

// newCLIContext returns a context with the default CLI timeout and its cancel function.
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// NewCommand creates the root switch command for physical switch operations.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch",
		Short: "Physical switch management operations",
		Long: `Manage physical network switches via platformd.

The switch subsystem provides:
  - Port listing and status monitoring
  - VLAN assignment on access-mode ports
  - Port administrative enable/disable

All commands communicate with the platformd REST API.

Examples:
  # List all ports on a switch
  platformctl switch list-ports --server-url https://platform:8443 --switch core-01

  # Get status of a specific port
  platformctl switch port-status --server-url https://platform:8443 --switch core-01 --port Eth1/3

  # Set access VLAN on a port
  platformctl switch set-vlan --server-url https://platform:8443 --switch core-01 --port Eth1/3 --vlan 200

  # Enable a port
  platformctl switch enable-port --server-url https://platform:8443 --switch core-01 --port Eth1/3

  # Disable a port
  platformctl switch disable-port --server-url https://platform:8443 --switch core-01 --port Eth1/3`,
	}

	cmd.AddCommand(newListPortsCommand(getFlags))
	cmd.AddCommand(newPortStatusCommand(getFlags))
	cmd.AddCommand(newSetVLANCommand(getFlags))
	cmd.AddCommand(newEnablePortCommand(getFlags))
	cmd.AddCommand(newDisablePortCommand(getFlags))

	return cmd
}

// newSwitchClient creates a switch SDK REST client from the provided flags.
// It resolves the CLI context for TLS configuration and builds an HTTP client
// with proper mTLS support.
func newSwitchClient(flags *switchFlags, getFlags func() *cli.CommonFlags) (*switchsdk.Client, error) {
	if flags.serverURL == "" {
		return nil, ErrServerURLRequired{}
	}

	httpClient, err := buildHTTPClient(getFlags)
	if err != nil {
		return nil, ErrClientCreateFailed{Cause: err}
	}

	client, err := switchsdk.NewClient(flags.serverURL, httpClient)
	if err != nil {
		return nil, ErrClientCreateFailed{Cause: err}
	}

	return client, nil
}

// buildHTTPClient creates an HTTP client with TLS configuration from the CLI context.
func buildHTTPClient(getFlags func() *cli.CommonFlags) (*http.Client, error) {
	commonFlags := getFlags()
	if commonFlags == nil || commonFlags.GetContext == nil {
		return &http.Client{}, nil
	}

	ctx, err := commonFlags.GetContext()
	if err != nil {
		// Fall back to default HTTP client if context is unavailable.
		return &http.Client{}, nil
	}

	if ctx.Remote == nil {
		return &http.Client{}, nil
	}

	tlsConfig, err := buildClientTLSConfig(ctx.Remote)
	if err != nil {
		return nil, ErrTLSConfigFailed{Cause: err}
	}

	if tlsConfig == nil {
		return &http.Client{}, nil
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// buildClientTLSConfig creates a TLS configuration from the remote context.
func buildClientTLSConfig(remote *cli.RemoteContext) (*tls.Config, error) {
	if remote.CACert == "" && remote.ClientCert == "" {
		return nil, nil
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load CA certificate for server verification.
	if remote.CACert != "" {
		caPEM, err := os.ReadFile(remote.CACert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, ErrTLSConfigFailed{Cause: err}
		}
		config.RootCAs = pool
	}

	// Load client certificate for mTLS.
	if remote.ClientCert != "" && remote.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(remote.ClientCert, remote.ClientKey)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}

// addServerURLFlag adds the --server-url flag to a command.
func addServerURLFlag(cmd *cobra.Command, flags *switchFlags) {
	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platformd REST API URL (required)")
}

// addSwitchFlag adds the --switch flag to a command.
func addSwitchFlag(cmd *cobra.Command, flags *switchFlags) {
	cmd.Flags().StringVar(&flags.switchName, "switch", "", "switch name (required)")
}

// addPortFlag adds the --port flag to a command.
func addPortFlag(cmd *cobra.Command, flags *switchFlags) {
	cmd.Flags().StringVar(&flags.port, "port", "", "port name, e.g. Eth1/3 (required)")
}
