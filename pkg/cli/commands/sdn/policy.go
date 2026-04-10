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

package sdn

import (
	"fmt"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdnclient "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// ErrInvalidPolicyType indicates an unrecognized policy type string.
type ErrInvalidPolicyType struct {
	Type string
}

func (e ErrInvalidPolicyType) Error() string {
	return fmt.Sprintf("invalid policy type: %s (valid: acl, qos, nat, firewall, routing)", e.Type)
}

// NewPolicyCommand creates the policy subcommand
func NewPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Network policy operations",
		Long: `Manage network policies for SDN bridges and ports.

The policy subsystem provides:
  - Apply, get, and list network policies
  - ACL, QoS, NAT, firewall, and routing policy types
  - Priority-based rule evaluation

Examples:
  # Apply a network policy
  platformctl sdn policy apply --id pol1 --name block-external --type acl --priority 100 --bridge br0

  # Get policy details
  platformctl sdn policy get pol1

  # List all policies
  platformctl sdn policy list`,
	}

	cmd.AddCommand(newPolicyApplyCommand(getFlags))
	cmd.AddCommand(newPolicyGetCommand(getFlags))
	cmd.AddCommand(newPolicyListCommand(getFlags))

	return cmd
}

func newPolicyApplyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		policyID    string
		name        string
		policyType  string
		description string
		priority    int
		enabled     bool
		bridgeID    string
	)

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a network policy",
		Long: `Apply a network policy to the SDN infrastructure.

Supported policy types: acl, qos, nat, firewall, routing

Examples:
  platformctl sdn policy apply --id pol1 --name block-external --type acl --priority 100 --bridge br0
  platformctl sdn policy apply --id pol2 --name rate-limit --type qos --priority 50 --bridge br0 --enabled --description "Rate limiting policy"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyApply(getFlags(), policyID, name, policyType,
				description, bridgeID, priority, enabled)
		},
	}

	cmd.Flags().StringVar(&policyID, "id", "", "Policy ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Policy name (required)")
	cmd.Flags().StringVar(&policyType, "type", "", "Policy type: acl, qos, nat, firewall, routing (required)")
	cmd.Flags().StringVar(&description, "description", "", "Policy description")
	cmd.Flags().IntVar(&priority, "priority", 0, "Policy priority (required)")
	cmd.Flags().BoolVar(&enabled, "enabled", false, "Enable the policy immediately")
	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID to apply policy to (required)")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("type")
	cmd.MarkFlagRequired("priority")
	cmd.MarkFlagRequired("bridge")

	return cmd
}

func newPolicyGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <policy-id>",
		Short: "Get policy details",
		Long: `Get detailed information about a network policy.

Examples:
  platformctl sdn policy get pol1
  platformctl sdn policy get pol1 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyGet(getFlags(), args[0])
		},
	}
}

func newPolicyListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		policyType string
		targetID   string
		limit      int
		cursor     string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List network policies",
		Long: `List network policies with optional filtering.

Examples:
  platformctl sdn policy list
  platformctl sdn policy list --type acl
  platformctl sdn policy list --target br0 --limit 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyList(getFlags(), policyType, targetID, limit, cursor)
		},
	}

	cmd.Flags().StringVar(&policyType, "type", "", "Filter by policy type")
	cmd.Flags().StringVar(&targetID, "target", "", "Filter by target ID")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of results")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor")

	return cmd
}

// Implementation functions
//
// Network policies are applied via the SDN service's ApplyPolicy RPC.
// The server translates policies into OpenFlow rules and tracks them
// in its policy store for retrieval and management.

func runPolicyApply(flags *cli.CommonFlags, policyID, name, policyType,
	description, bridgeID string, priority int, enabled bool) error {

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnclient.NewClientFromGRPC(base.Client().SDN())

	pbType, err := parsePolicyType(policyType)
	if err != nil {
		return err
	}

	config := &platformv1.PolicyConfig{
		Name:        name,
		Description: description,
		Type:        pbType,
		Priority:    int32(priority),
		Enabled:     enabled,
		Targets: []*platformv1.PolicyTarget{
			{
				Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE,
				Id:   bridgeID,
			},
		},
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdnClient.ApplyPolicy(ctx, policyID, config)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "policy apply", Err: err}
	}

	return base.Output(resp)
}

// parsePolicyType converts a user-facing policy type string to a protobuf enum.
func parsePolicyType(s string) (platformv1.PolicyType, error) {
	policyTypes := map[string]platformv1.PolicyType{
		"acl":      platformv1.PolicyType_POLICY_TYPE_ACL,
		"qos":      platformv1.PolicyType_POLICY_TYPE_QOS,
		"nat":      platformv1.PolicyType_POLICY_TYPE_NAT,
		"firewall": platformv1.PolicyType_POLICY_TYPE_FIREWALL,
		"routing":  platformv1.PolicyType_POLICY_TYPE_ROUTING,
	}
	pt, ok := policyTypes[s]
	if !ok {
		return platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED, ErrInvalidPolicyType{Type: s}
	}
	return pt, nil
}

func runPolicyGet(flags *cli.CommonFlags, policyID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnclient.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdnClient.GetPolicy(ctx, policyID)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "policy get", Err: err}
	}

	return base.Output(resp)
}

func runPolicyList(flags *cli.CommonFlags, policyType, targetID string, limit int, cursor string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnclient.NewClientFromGRPC(base.Client().SDN())

	var pagination *platformv1.PaginationRequest
	if limit > 0 || cursor != "" {
		pagination = &platformv1.PaginationRequest{
			PageSize: uint32(limit),
		}
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdnClient.ListPolicies(ctx, policyType, targetID, pagination)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "policy list", Err: err}
	}

	return base.Output(resp)
}
