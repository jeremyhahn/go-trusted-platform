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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrGetKeyPolicyFailed is returned when getting key policy fails
type ErrGetKeyPolicyFailed struct {
	KeyID string
	Err   error
}

func (e ErrGetKeyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to get policy for key %s: %v", e.KeyID, e.Err)
}

func (e ErrGetKeyPolicyFailed) Unwrap() error {
	return e.Err
}

// ErrSetKeyPolicyFailed is returned when setting key policy fails
type ErrSetKeyPolicyFailed struct {
	KeyID string
	Err   error
}

func (e ErrSetKeyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to set policy for key %s: %v", e.KeyID, e.Err)
}

func (e ErrSetKeyPolicyFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidDuration is returned when a duration string is invalid
type ErrInvalidDuration struct {
	Value string
	Err   error
}

func (e ErrInvalidDuration) Error() string {
	return fmt.Sprintf("invalid duration format: %s: %v", e.Value, e.Err)
}

// ErrNegativeDuration is returned when a duration is negative
var ErrNegativeDuration = errors.New("duration cannot be negative")

// keyPolicyOutput is the CLI presentation of a key access policy.
type keyPolicyOutput struct {
	KeyID             string   `json:"key_id"`
	Version           int      `json:"version"`
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string `json:"denied_principals,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	RotationRequired  bool     `json:"rotation_required"`
	MaxUsageCount     uint64   `json:"max_usage_count,omitempty"`
	RequireMFA        bool     `json:"require_mfa"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
}

// newKeyPolicyOutput converts the SDK key policy for display.
func newKeyPolicyOutput(policy *kms.KeyPolicy) *keyPolicyOutput {
	out := &keyPolicyOutput{
		KeyID:             policy.KeyID,
		Version:           policy.Version,
		AllowedOperations: keyUsageStrings(policy.AllowedOperations),
		AllowedPrincipals: policy.AllowedPrincipals,
		DeniedPrincipals:  policy.DeniedPrincipals,
		RotationRequired:  policy.RotationRequired,
		MaxUsageCount:     policy.MaxUsageCount,
		RequireMFA:        policy.RequireMFA,
	}
	out.ExpiresAt = formatTimeOrEmpty(policy.ExpiresAt)
	out.UpdatedAt = formatTimeOrEmpty(policy.UpdatedAt)
	return out
}

// newKeyPolicyCommand creates the key policy subcommand group
func newKeyPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage key access policies",
		Long: `Get or set access control policies for cryptographic keys.

Key policies define who can use a key and for what operations. Policies
support allowed/denied principals, operation restrictions, and expiration.`,
	}

	cmd.AddCommand(newKeyPolicyGetCommand(getFlags))
	cmd.AddCommand(newKeyPolicySetCommand(getFlags))

	return cmd
}

// newKeyPolicyGetCommand creates the policy get subcommand
func newKeyPolicyGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <key-id>",
		Short: "Get key access policy",
		Long: `Retrieve the access control policy for a cryptographic key.

Examples:
  platformctl kms key policy get my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyPolicyGet(getFlags(), args[0])
		},
	}

	return cmd
}

// runKeyPolicyGet opens the SDK connection and delegates to executeKeyPolicyGet.
func runKeyPolicyGet(flags *cli.CommonFlags, keyID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyPolicyGet(base.Context(), client, base.Printer(), keyID)
}

// executeKeyPolicyGet retrieves and prints a key policy.
func executeKeyPolicyGet(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, keyID string) error {
	policy, err := client.GetKeyPolicy(ctx, keyID)
	if err != nil {
		return ErrGetKeyPolicyFailed{KeyID: keyID, Err: err}
	}
	return printer.Print(newKeyPolicyOutput(policy))
}

// newKeyPolicySetCommand creates the policy set subcommand
func newKeyPolicySetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var operations []string
	var allowPrincipals []string
	var denyPrincipals []string
	var expiresIn string
	var rotationRequired bool
	var maxUsageCount uint64
	var requireMFA bool

	cmd := &cobra.Command{
		Use:   "set <key-id>",
		Short: "Set key access policy",
		Long: `Set or update the access control policy for a cryptographic key.

Policies support allowed and denied principals, operation restrictions, expiration,
rotation requirements, usage limits, and MFA requirements for sensitive operations.

Examples:
  platformctl kms key policy set my-key --operation encrypt --allow-principal user:alice

  platformctl kms key policy set my-key --operation sign --expires-in 7d --require-mfa`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyPolicySet(getFlags(), args[0], keyPolicySetOptions{
				Operations:       operations,
				AllowPrincipals:  allowPrincipals,
				DenyPrincipals:   denyPrincipals,
				ExpiresIn:        expiresIn,
				RotationRequired: rotationRequired,
				MaxUsageCount:    maxUsageCount,
				RequireMFA:       requireMFA,
			})
		},
	}

	cmd.Flags().StringArrayVar(&operations, "operation", nil, "allowed operation (encrypt, decrypt, sign, verify, wrap-key, derive-key)")
	cmd.Flags().StringArrayVar(&allowPrincipals, "allow-principal", nil, "allowed principal (e.g., user:alice, role:admin)")
	cmd.Flags().StringArrayVar(&denyPrincipals, "deny-principal", nil, "denied principal")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "policy expiration duration (e.g., 24h, 7d)")
	cmd.Flags().BoolVar(&rotationRequired, "rotation-required", false, "require key rotation")
	cmd.Flags().Uint64Var(&maxUsageCount, "max-usage", 0, "maximum number of times the key can be used")
	cmd.Flags().BoolVar(&requireMFA, "require-mfa", false, "require MFA for key operations")

	return cmd
}

// keyPolicySetOptions collects the policy set flag values.
type keyPolicySetOptions struct {
	Operations       []string
	AllowPrincipals  []string
	DenyPrincipals   []string
	ExpiresIn        string
	RotationRequired bool
	MaxUsageCount    uint64
	RequireMFA       bool
}

// runKeyPolicySet opens the SDK connection and delegates to executeKeyPolicySet.
func runKeyPolicySet(flags *cli.CommonFlags, keyID string, opts keyPolicySetOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyPolicySet(base.Context(), client, base.Printer(), keyID, opts)
}

// executeKeyPolicySet builds and applies a key policy via the quicbaas
// SDK KMS client.
func executeKeyPolicySet(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, keyID string, opts keyPolicySetOptions) error {
	allowedOps, err := parseSDKKeyUsages(opts.Operations)
	if err != nil {
		return err
	}

	policy := &kms.KeyPolicy{
		KeyID:             keyID,
		AllowedOperations: allowedOps,
		AllowedPrincipals: opts.AllowPrincipals,
		DeniedPrincipals:  opts.DenyPrincipals,
		RotationRequired:  opts.RotationRequired,
		MaxUsageCount:     opts.MaxUsageCount,
		RequireMFA:        opts.RequireMFA,
	}

	if opts.ExpiresIn != "" {
		duration, derr := parseDuration(opts.ExpiresIn)
		if derr != nil {
			return ErrInvalidDuration{Value: opts.ExpiresIn, Err: derr}
		}
		policy.ExpiresAt = time.Now().Add(duration)
	}

	if err := client.SetKeyPolicy(ctx, &kms.SetKeyPolicyRequest{
		KeyID:  keyID,
		Policy: policy,
	}); err != nil {
		return ErrSetKeyPolicyFailed{KeyID: keyID, Err: err}
	}

	printer.PrintSuccess(fmt.Sprintf("Key %s policy updated", keyID))
	return nil
}

// parseDuration parses a duration string supporting days (d), hours (h), minutes (m), seconds (s)
func parseDuration(s string) (time.Duration, error) {
	// Handle day suffix
	if strings.HasSuffix(s, "d") {
		days := s[:len(s)-1]
		var d int
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, err
		}
		if d < 0 {
			return 0, ErrNegativeDuration
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	// Use standard time.ParseDuration for h, m, s
	duration, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if duration < 0 {
		return 0, ErrNegativeDuration
	}
	return duration, nil
}
