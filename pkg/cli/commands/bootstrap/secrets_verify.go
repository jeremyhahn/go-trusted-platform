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
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// secretsVerifyFlags contains flags for the verify command
type secretsVerifyFlags struct {
	configPath  string
	dryRun      bool
	failFast    bool
	showSecrets bool
}

// newSecretsVerifyCommand creates the secrets verify command
func newSecretsVerifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &secretsVerifyFlags{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify all secrets are resolvable",
		Long: `Verify that all secret URIs in the configuration can be resolved.

This command attempts to resolve each secret URI and reports success or failure.
It is useful for validating configuration before deployment or after migration.

The verification process:
  1. Scans configuration for all secret URIs
  2. Attempts to resolve each URI using the appropriate resolver
  3. Reports success/failure for each secret
  4. Returns error exit code if any secrets fail

Examples:
  # Verify all secrets
  platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml

  # Verify without actually resolving (check resolver availability only)
  platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml --dry-run

  # Stop on first failure
  platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml --fail-fast

  # Show resolved secret values (for debugging)
  platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml --show-secrets`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSecretsVerify(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.configPath, "config", "", "Path to configuration file (required)")
	cmd.Flags().BoolVar(&cmdFlags.dryRun, "dry-run", false, "Check resolver availability without resolving")
	cmd.Flags().BoolVar(&cmdFlags.failFast, "fail-fast", false, "Stop verification on first failure")
	cmd.Flags().BoolVar(&cmdFlags.showSecrets, "show-secrets", false, "Show resolved secret values (use with caution)")

	cmd.MarkFlagRequired("config") //nolint:errcheck

	return cmd
}

// verificationResult holds the result of verifying a single secret
type verificationResult struct {
	path     string
	uri      string
	scheme   string
	success  bool
	value    string
	errorMsg string
}

// runSecretsVerify executes the secrets verification
func runSecretsVerify(flags *cli.CommonFlags, cmdFlags *secretsVerifyFlags) error {
	if cmdFlags.configPath == "" {
		return ErrConfigPathRequired{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	printer := base.Printer()
	ctx := base.Context()

	// Read configuration file
	configData, err := os.ReadFile(cmdFlags.configPath)
	if err != nil {
		return ErrConfigFileReadFailed{Path: cmdFlags.configPath, Err: err}
	}

	// Scan for secrets
	secrets := scanConfigForSecrets(configData)
	if len(secrets) == 0 {
		printer.PrintInfo("No secret URIs found in configuration")
		return nil
	}

	printer.PrintInfo(fmt.Sprintf("Verifying %d secret(s) in %s", len(secrets), cmdFlags.configPath))
	fmt.Println()

	// Verify each secret
	var results []verificationResult
	var failedCount int

	for _, secret := range secrets {
		result := verificationResult{
			path:   secret.path,
			uri:    secret.uri,
			scheme: detectScheme(secret.uri),
		}

		if cmdFlags.dryRun {
			// Dry run - only check resolver availability
			result.success = isResolverAvailable(result.scheme)
			if !result.success {
				result.errorMsg = "resolver not available"
				failedCount++
			}
		} else {
			// Actually attempt resolution
			value, resolveErr := resolveSecretValue(ctx, base.Client(), secret.uri)
			if resolveErr != nil {
				result.success = false
				result.errorMsg = resolveErr.Error()
				failedCount++

				if cmdFlags.failFast {
					printer.PrintError(fmt.Sprintf("FAILED: %s - %s", secret.path, resolveErr.Error()))
					return ErrSecretVerificationFailed{
						FailedCount: 1,
						TotalCount:  len(secrets),
					}
				}
			} else {
				result.success = true
				if cmdFlags.showSecrets {
					result.value = string(value)
				} else {
					result.value = maskValue(value)
				}
			}
		}

		results = append(results, result)

		// Print progress in table mode
		if flags.OutputFormat == cli.OutputFormatTable {
			if result.success {
				printer.PrintSuccess(fmt.Sprintf("OK: %s", result.path))
			} else {
				printer.PrintError(fmt.Sprintf("FAILED: %s - %s", result.path, result.errorMsg))
			}
		}
	}

	fmt.Println()

	// Output results
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			ConfigPath   string `json:"config_path" yaml:"config_path"`
			DryRun       bool   `json:"dry_run" yaml:"dry_run"`
			TotalSecrets int    `json:"total_secrets" yaml:"total_secrets"`
			Verified     int    `json:"verified" yaml:"verified"`
			Failed       int    `json:"failed" yaml:"failed"`
			Results      []struct {
				Path    string `json:"path" yaml:"path"`
				Scheme  string `json:"scheme" yaml:"scheme"`
				Success bool   `json:"success" yaml:"success"`
				Value   string `json:"value,omitempty" yaml:"value,omitempty"`
				Error   string `json:"error,omitempty" yaml:"error,omitempty"`
			} `json:"results" yaml:"results"`
		}{
			ConfigPath:   cmdFlags.configPath,
			DryRun:       cmdFlags.dryRun,
			TotalSecrets: len(secrets),
			Verified:     len(secrets) - failedCount,
			Failed:       failedCount,
		}

		for _, r := range results {
			entry := struct {
				Path    string `json:"path" yaml:"path"`
				Scheme  string `json:"scheme" yaml:"scheme"`
				Success bool   `json:"success" yaml:"success"`
				Value   string `json:"value,omitempty" yaml:"value,omitempty"`
				Error   string `json:"error,omitempty" yaml:"error,omitempty"`
			}{
				Path:    r.path,
				Scheme:  r.scheme,
				Success: r.success,
			}
			if r.success && cmdFlags.showSecrets {
				entry.Value = r.value
			}
			if !r.success {
				entry.Error = r.errorMsg
			}
			output.Results = append(output.Results, entry)
		}

		if err := printer.Print(output); err != nil {
			return err
		}

	default:
		// Summary
		if failedCount == 0 {
			printer.PrintSuccess(fmt.Sprintf("All %d secret(s) verified successfully", len(secrets)))
		} else {
			printer.PrintError(fmt.Sprintf("%d of %d secret(s) failed verification", failedCount, len(secrets)))
		}
	}

	if failedCount > 0 {
		return ErrSecretVerificationFailed{
			FailedCount: failedCount,
			TotalCount:  len(secrets),
		}
	}

	return nil
}

// maskValue masks a secret value for safe display
func maskValue(value []byte) string {
	if len(value) == 0 {
		return "(empty)"
	}
	if len(value) <= 4 {
		return "****"
	}
	return string(value[:2]) + "****" + string(value[len(value)-2:])
}
