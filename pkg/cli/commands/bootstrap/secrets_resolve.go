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

package bootstrap

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// secretsResolveFlags contains flags for the resolve command
type secretsResolveFlags struct {
	masked bool
	raw    bool
}

// newSecretsResolveCommand creates the secrets resolve command
func newSecretsResolveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &secretsResolveFlags{}

	cmd := &cobra.Command{
		Use:   "resolve <uri>",
		Short: "Resolve a single secret URI",
		Long: `Resolve a single secret URI and display the result.

This command is useful for testing secret resolution and debugging configuration.
By default, the resolved value is masked for security.

Supported URI schemes:
  - kms://       - Local KMS-managed secrets
  - remote-kms:// - Remote KMS-managed secrets
  - env://       - Environment variable references
  - autogen://   - Auto-generated secrets
  - encrypted:// - Encrypted secrets

Examples:
  # Resolve a KMS secret (masked)
  platformctl bootstrap secrets resolve "kms://config/db/password"

  # Resolve and show full value (use with caution)
  platformctl bootstrap secrets resolve "kms://config/db/password" --raw

  # Resolve environment variable
  platformctl bootstrap secrets resolve "env://DATABASE_PASSWORD"

  # Test auto-generation spec
  platformctl bootstrap secrets resolve "autogen://password?length=32"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSecretsResolve(flags, args[0], cmdFlags)
		},
	}

	cmd.Flags().BoolVar(&cmdFlags.masked, "masked", true, "Mask the resolved value (default)")
	cmd.Flags().BoolVar(&cmdFlags.raw, "raw", false, "Show the full resolved value (use with caution)")

	return cmd
}

// runSecretsResolve executes the secrets resolve command
func runSecretsResolve(flags *cli.CommonFlags, uri string, cmdFlags *secretsResolveFlags) error {
	if uri == "" {
		return ErrSecretURIRequired{}
	}

	// Validate URI format
	scheme := detectScheme(uri)
	if scheme == "unknown" {
		return ErrInvalidSecretURI{
			URI:    uri,
			Reason: "unknown or missing scheme (expected kms://, env://, autogen://, remote-kms://, or encrypted://)",
		}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	printer := base.Printer()
	ctx := base.Context()

	// Check resolver availability
	if !isResolverAvailable(scheme) {
		return ErrResolverNotAvailable{Scheme: scheme}
	}

	// Resolve the secret
	value, err := resolveSecretValue(ctx, base.Client(), uri)
	if err != nil {
		return ErrSecretResolutionFailed{URI: maskSecretURI(uri), Err: err}
	}

	// Determine display value
	displayValue := string(value)
	if cmdFlags.masked && !cmdFlags.raw {
		displayValue = maskValue(value)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		result := struct {
			URI      string `json:"uri" yaml:"uri"`
			Scheme   string `json:"scheme" yaml:"scheme"`
			Resolved bool   `json:"resolved" yaml:"resolved"`
			Value    string `json:"value" yaml:"value"`
			Length   int    `json:"length" yaml:"length"`
			Masked   bool   `json:"masked" yaml:"masked"`
		}{
			URI:      maskSecretURI(uri),
			Scheme:   scheme,
			Resolved: true,
			Value:    displayValue,
			Length:   len(value),
			Masked:   cmdFlags.masked && !cmdFlags.raw,
		}
		return printer.Print(result)

	default:
		printer.PrintSuccess("Secret resolved successfully")
		fmt.Println()
		printer.PrintKeyValue("URI", maskSecretURI(uri))
		printer.PrintKeyValue("Scheme", scheme)
		printer.PrintKeyValue("Length", fmt.Sprintf("%d bytes", len(value)))
		printer.PrintKeyValue("Value", displayValue)

		if cmdFlags.masked && !cmdFlags.raw {
			fmt.Println()
			printer.PrintInfo("Use --raw to show the full secret value")
		}
	}

	return nil
}
