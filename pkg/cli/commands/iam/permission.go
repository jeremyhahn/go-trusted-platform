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

package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
)

// NewPermissionCommand creates the permission command group.
func NewPermissionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "permission",
		Short: "Check IAM permissions",
		Long: `Check whether a subject may perform an action on a resource.

The check is answered by the daemon's IAM service from the subject's
roles and groups and the tenant's policies.`,
	}

	cmd.AddCommand(newPermissionCheckCommand(getFlags))

	return cmd
}

// permissionCheckRequest holds the flag values of 'iam permission check'.
type permissionCheckRequest struct {
	tenantID   string
	subjectID  string
	roles      string
	groups     string
	action     string
	resource   string
	context    string
	attributes string
}

// validate reports the first required value that is missing.
func (r *permissionCheckRequest) validate() error {
	if r.tenantID == "" {
		return ErrMissingTenantID{}
	}
	if r.subjectID == "" {
		return &MessageError{Msg: "subject ID is required"}
	}
	if r.action == "" {
		return &MessageError{Msg: "action is required"}
	}
	if r.resource == "" {
		return &MessageError{Msg: "resource is required"}
	}
	return nil
}

// toProto converts the flag values into the IAM CheckPermission request.
func (r *permissionCheckRequest) toProto() *platformv1.CheckIAMPermissionRequest {
	return &platformv1.CheckIAMPermissionRequest{
		TenantId:   r.tenantID,
		SubjectId:  r.subjectID,
		Roles:      parseStringSlice(r.roles),
		Groups:     parseStringSlice(r.groups),
		Action:     r.action,
		Resource:   r.resource,
		Context:    parseAttributes(r.context),
		Attributes: parseAttributes(r.attributes),
	}
}

// PermissionCheckResult is the JSON/YAML output of 'iam permission check'.
type PermissionCheckResult struct {
	Allowed          bool   `json:"allowed" yaml:"allowed"`
	MatchedPolicy    string `json:"matched_policy,omitempty" yaml:"matched_policy,omitempty"`
	MatchedRule      string `json:"matched_rule,omitempty" yaml:"matched_rule,omitempty"`
	Reason           string `json:"reason,omitempty" yaml:"reason,omitempty"`
	EvaluationTimeNs int64  `json:"evaluation_time_ns" yaml:"evaluation_time_ns"`
}

func newPermissionCheckCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	req := &permissionCheckRequest{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check whether a subject is allowed an action on a resource",
		Long: `Check whether a subject is allowed to perform an action on a resource
within a tenant.

Roles and groups are the subject's role and group IDs to evaluate. Context
and attributes are comma-separated key=value pairs passed to the policy
evaluation.

Example:
  platformctl iam permission check --tenant acme --subject user-123 --roles role-1 --action read --resource users
  platformctl iam permission check --tenant acme --subject user-123 --groups ops --action write --resource vms --context ip=10.0.0.1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := req.validate(); err != nil {
				return err
			}
			return runPermissionCheck(getFlags(), req)
		},
	}

	cmd.Flags().StringVar(&req.tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&req.subjectID, "subject", "", "subject/user ID (required)")
	cmd.Flags().StringVar(&req.roles, "roles", "", "comma-separated role IDs of the subject")
	cmd.Flags().StringVar(&req.groups, "groups", "", "comma-separated group IDs of the subject")
	cmd.Flags().StringVar(&req.action, "action", "", "action to check (required)")
	cmd.Flags().StringVar(&req.resource, "resource", "", "resource to check (required)")
	cmd.Flags().StringVar(&req.context, "context", "", "comma-separated key=value request context")
	cmd.Flags().StringVar(&req.attributes, "attributes", "", "comma-separated key=value subject attributes")

	return cmd
}

// checkPermission asks the IAM service and converts its answer.
func checkPermission(ctx context.Context, c *iamsvc.Client, req *permissionCheckRequest) (*PermissionCheckResult, error) {
	resp, err := c.CheckPermission(ctx, req.toProto())
	if err != nil {
		return nil, &WrappedError{Msg: "failed to check permission", Err: err}
	}
	return &PermissionCheckResult{
		Allowed:          resp.GetAllowed(),
		MatchedPolicy:    resp.GetMatchedPolicy(),
		MatchedRule:      resp.GetMatchedRule(),
		Reason:           resp.GetReason(),
		EvaluationTimeNs: resp.GetEvaluationTimeNs(),
	}, nil
}

func runPermissionCheck(flags *cli.CommonFlags, req *permissionCheckRequest) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	result, err := checkPermission(base.Context(), iamsvc.NewClientFromGRPC(base.Client().IAM()), req)
	if err != nil {
		return err
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		fmt.Println()
		if result.Allowed {
			printer.PrintSuccess("Access ALLOWED")
		} else {
			printer.PrintError("Access DENIED")
		}
		fmt.Println()
		printer.PrintKeyValue("Subject", req.subjectID)
		printer.PrintKeyValue("Action", req.action)
		printer.PrintKeyValue("Resource", req.resource)
		if result.MatchedPolicy != "" {
			printer.PrintKeyValue("Matched Policy", result.MatchedPolicy)
		}
		if result.MatchedRule != "" {
			printer.PrintKeyValue("Matched Rule", result.MatchedRule)
		}
		if result.Reason != "" {
			printer.PrintKeyValue("Reason", result.Reason)
		}
		printer.PrintKeyValue("Evaluation Time", (time.Duration(result.EvaluationTimeNs) * time.Nanosecond).String())
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
