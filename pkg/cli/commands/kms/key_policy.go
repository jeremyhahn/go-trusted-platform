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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrKeyPolicyNotImplemented is returned when key policy operations are not yet implemented
type ErrKeyPolicyNotImplemented struct{}

func (e ErrKeyPolicyNotImplemented) Error() string {
	return "key policy operations are not yet implemented in the platform KMS service"
}

// ErrGetKeyPolicyFailed is returned when getting key policy fails
type ErrGetKeyPolicyFailed struct {
	KeyID string
	Err   error
}

func (e ErrGetKeyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to get policy for key %s: %v", e.KeyID, e.Err)
}

// ErrSetKeyPolicyFailed is returned when setting key policy fails
type ErrSetKeyPolicyFailed struct {
	KeyID string
	Err   error
}

func (e ErrSetKeyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to set policy for key %s: %v", e.KeyID, e.Err)
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

// newKeyPolicyCommand creates the key policy subcommand group
func newKeyPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage key access policies (not yet implemented)",
		Long: `Get or set access control policies for cryptographic keys.

NOTE: This command is not yet implemented in the platform KMS service.

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
		Short: "Get key access policy (not yet implemented)",
		Long: `Retrieve the access control policy for a cryptographic key.

NOTE: This command is not yet implemented in the platform KMS service.

Examples:
  platformctl kms key policy get my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyPolicyNotImplemented{}
		},
	}

	return cmd
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
		Short: "Set key access policy (not yet implemented)",
		Long: `Set or update the access control policy for a cryptographic key.

NOTE: This command is not yet implemented in the platform KMS service.

Policies support allowed and denied principals, operation restrictions, expiration,
rotation requirements, usage limits, and MFA requirements for sensitive operations.

Examples:
  platformctl kms key policy set my-key --operation encrypt --allow-principal user:alice`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyPolicyNotImplemented{}
		},
	}

	cmd.Flags().StringArrayVarP(&operations, "operation", "o", nil, "allowed operation (encrypt, decrypt, sign, verify, wrap-key, derive-key)")
	cmd.Flags().StringArrayVar(&allowPrincipals, "allow-principal", nil, "allowed principal (e.g., user:alice, role:admin)")
	cmd.Flags().StringArrayVar(&denyPrincipals, "deny-principal", nil, "denied principal")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "policy expiration duration (e.g., 24h, 7d)")
	cmd.Flags().BoolVar(&rotationRequired, "rotation-required", false, "require key rotation")
	cmd.Flags().Uint64Var(&maxUsageCount, "max-usage", 0, "maximum number of times the key can be used")
	cmd.Flags().BoolVar(&requireMFA, "require-mfa", false, "require MFA for key operations")

	return cmd
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
