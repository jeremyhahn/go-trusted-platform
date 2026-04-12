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
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewPolicyCommand creates the policy management command group
func NewPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage authorization policies",
		Long: `Manage authorization policies in the Identity and Access Management system.

Policies define access control rules that determine what actions subjects
can perform on resources. Policies are written in YAML and can include
conditions, time constraints, and attribute-based access control.

Supported operations:
  - create: Create a new policy from a YAML file
  - get: Retrieve policy details
  - list: List all policies for a tenant
  - update: Update an existing policy
  - delete: Delete a policy
  - validate: Validate a policy YAML file
  - test: Test a policy against a specific request`,
	}

	cmd.AddCommand(newPolicyCreateCommand(getFlags))
	cmd.AddCommand(newPolicyGetCommand(getFlags))
	cmd.AddCommand(newPolicyListCommand(getFlags))
	cmd.AddCommand(newPolicyUpdateCommand(getFlags))
	cmd.AddCommand(newPolicyDeleteCommand(getFlags))
	cmd.AddCommand(newPolicyValidateCommand(getFlags))
	cmd.AddCommand(newPolicyTestCommand(getFlags))

	return cmd
}

// newPolicyCreateCommand creates the policy create subcommand
func newPolicyCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var description string
	var priority int32
	var file string
	var labels string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new policy",
		Long: `Create a new authorization policy from a YAML specification file.

The policy spec YAML file should contain the policy rules including:
  - Effect (allow/deny)
  - Subjects (who the policy applies to)
  - Actions (what operations are permitted)
  - Resources (what resources are affected)
  - Conditions (optional constraints)

Example:
  platformctl iam policy create --tenant acme --name admin-access --file admin-policy.yaml --priority 100`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if name == "" {
				return ErrMissingPolicyName{}
			}
			if file == "" {
				return ErrInvalidPolicySpec{Reason: "policy file is required"}
			}
			flags := getFlags()
			return runPolicyCreate(flags, tenantID, name, description, priority, file, labels)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "policy name (required)")
	cmd.Flags().StringVar(&description, "description", "", "policy description")
	cmd.Flags().Int32Var(&priority, "priority", 0, "policy priority (higher = evaluated first)")
	cmd.Flags().StringVar(&file, "file", "", "path to policy YAML file (required)")
	cmd.Flags().StringVar(&labels, "labels", "", "comma-separated key=value labels")

	return cmd
}

// newPolicyGetCommand creates the policy get subcommand
func newPolicyGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-id> <policy-name>",
		Short: "Get policy information",
		Long: `Retrieve information about a specific policy by tenant ID and policy name.

Example:
  platformctl iam policy get acme admin-access`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPolicyGet(flags, args[0], args[1])
		},
	}

	return cmd
}

// newPolicyListCommand creates the policy list subcommand
func newPolicyListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var page uint32
	var pageSize uint32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List policies",
		Long: `Display a list of policies for a tenant with pagination support.

Example:
  platformctl iam policy list --tenant acme --page-size 50`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			flags := getFlags()
			return runPolicyList(flags, tenantID, page, pageSize)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().Uint32VarP(&page, "page", "p", 1, "page number")
	cmd.Flags().Uint32VarP(&pageSize, "page-size", "s", 50, "maximum number of policies per page")

	return cmd
}

// newPolicyUpdateCommand creates the policy update subcommand
func newPolicyUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var description string
	var priority int32
	var file string
	var labels string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a policy",
		Long: `Update an existing policy's settings or specification.

If a file is provided, the policy specification will be replaced.
Only specified fields will be updated.

Example:
  platformctl iam policy update --tenant acme --name admin-access --file updated-policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if name == "" {
				return ErrMissingPolicyName{}
			}
			flags := getFlags()
			return runPolicyUpdate(flags, tenantID, name, description, priority, file, labels)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "policy name (required)")
	cmd.Flags().StringVar(&description, "description", "", "new policy description")
	cmd.Flags().Int32Var(&priority, "priority", 0, "new policy priority")
	cmd.Flags().StringVar(&file, "file", "", "path to updated policy YAML file")
	cmd.Flags().StringVar(&labels, "labels", "", "comma-separated key=value labels")

	return cmd
}

// newPolicyDeleteCommand creates the policy delete subcommand
func newPolicyDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <tenant-id> <policy-name>",
		Short: "Delete a policy",
		Long: `Delete a policy from a tenant.

WARNING: This operation is destructive and cannot be undone.
Deleting a policy may affect access control for resources.

Example:
  platformctl iam policy delete acme admin-access`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runPolicyDelete(flags, args[0], args[1])
		},
	}

	return cmd
}

// newPolicyValidateCommand creates the policy validate subcommand
func newPolicyValidateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var file string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a policy YAML file",
		Long: `Validate a policy YAML file without creating or updating.

This command checks the policy specification for syntax errors
and validates that all referenced resources and subjects exist.

Example:
  platformctl iam policy validate --tenant acme --file new-policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if file == "" {
				return ErrInvalidPolicySpec{Reason: "policy file is required"}
			}
			flags := getFlags()
			return runPolicyValidate(flags, tenantID, file)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "path to policy YAML file (required)")

	return cmd
}

// newPolicyTestCommand creates the policy test subcommand
func newPolicyTestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var subjectID string
	var roles string
	var groups string
	var action string
	var resource string
	var context string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test a policy against a request",
		Long: `Test policies by simulating an authorization request.

This command evaluates all applicable policies for the given subject,
action, and resource to determine if the request would be allowed.

Example:
  platformctl iam policy test --tenant acme --subject user-123 --action read --resource documents/secret.pdf
  platformctl iam policy test --tenant acme --subject user-456 --roles admin,user --action write --resource /api/users`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if subjectID == "" {
				return fmt.Errorf("subject ID is required")
			}
			if action == "" {
				return fmt.Errorf("action is required")
			}
			if resource == "" {
				return fmt.Errorf("resource is required")
			}
			flags := getFlags()
			return runPolicyTest(flags, tenantID, subjectID, roles, groups, action, resource, context)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&subjectID, "subject", "", "subject/user ID to test (required)")
	cmd.Flags().StringVar(&roles, "roles", "", "comma-separated roles to include")
	cmd.Flags().StringVar(&groups, "groups", "", "comma-separated groups to include")
	cmd.Flags().StringVar(&action, "action", "", "action to test (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "resource to test (required)")
	cmd.Flags().StringVar(&context, "context", "", "comma-separated key=value context attributes")

	return cmd
}

func runPolicyCreate(flags *cli.CommonFlags, tenantID, name, description string, priority int32, file, labels string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Read policy spec from file
	specYAML, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	policy, err := sdkClient.CreatePolicyDomain(ctx, tenantID, name, description, priority, specYAML, parseAttributes(labels))
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(policy)

	case cli.OutputFormatTable:
		if policy != nil {
			printer.PrintSuccess(fmt.Sprintf("Policy created successfully: %s", policy.Name))
			fmt.Println()
			printPolicyDetails(printer, policy)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runPolicyGet(flags *cli.CommonFlags, tenantID, policyName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	policy, err := sdkClient.GetPolicyDomain(ctx, tenantID, policyName)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(policy)

	case cli.OutputFormatTable:
		if policy != nil {
			printPolicyDetails(printer, policy)
			if len(policy.SpecYAML) > 0 {
				fmt.Println()
				printer.PrintKeyValue("Policy Spec", "")
				fmt.Println(string(policy.SpecYAML))
			}
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runPolicyList(flags *cli.CommonFlags, tenantID string, page, pageSize uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.ListPoliciesDomain(ctx, tenantID, page, pageSize)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if len(result.Policies) == 0 {
			printer.PrintInfo("No policies found")
			return nil
		}

		table := cli.NewTableData("Name", "Tenant", "Priority", "Description", "Created At")
		for _, policy := range result.Policies {
			desc := truncateString(policy.Description, 40)
			table.AddRow(
				policy.Name,
				policy.TenantID,
				fmt.Sprintf("%d", policy.Priority),
				desc,
				formatTimestamp(policy.CreatedAt),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", result.Total))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runPolicyUpdate(flags *cli.CommonFlags, tenantID, name, description string, priority int32, file, labels string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	var specYAML []byte
	// Read policy spec from file if provided
	if file != "" {
		var readErr error
		specYAML, readErr = os.ReadFile(file)
		if readErr != nil {
			return fmt.Errorf("failed to read policy file: %w", readErr)
		}
	}

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	policy, err := sdkClient.UpdatePolicyDomain(ctx, tenantID, name, description, priority, specYAML, parseAttributes(labels))
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(policy)

	case cli.OutputFormatTable:
		if policy != nil {
			printer.PrintSuccess(fmt.Sprintf("Policy updated successfully: %s", policy.Name))
			fmt.Println()
			printPolicyDetails(printer, policy)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runPolicyDelete(flags *cli.CommonFlags, tenantID, policyName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.DeletePolicyDomain(ctx, tenantID, policyName)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("Policy %s deleted successfully from tenant %s", policyName, tenantID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete policy %s from tenant %s", policyName, tenantID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runPolicyValidate(flags *cli.CommonFlags, tenantID, file string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Read policy spec from file
	specYAML, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.ValidatePolicyDomain(ctx, tenantID, specYAML)
	if err != nil {
		return fmt.Errorf("failed to validate policy: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if result.Valid {
			printer.PrintSuccess("Policy is valid")
		} else {
			printer.PrintError("Policy validation failed")
			if len(result.Errors) > 0 {
				fmt.Println()
				printer.PrintKeyValue("Errors", "")
				for i, e := range result.Errors {
					fmt.Printf("  %d. %s\n", i+1, e)
				}
			}
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runPolicyTest(flags *cli.CommonFlags, tenantID, subjectID, roles, groups, action, resource, context string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.TestPolicyDomain(ctx, tenantID, subjectID,
		parseStringSlice(roles), parseStringSlice(groups),
		action, resource, parseAttributes(context))
	if err != nil {
		return fmt.Errorf("failed to test policy: %w", err)
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
		printer.PrintKeyValue("Subject", subjectID)
		printer.PrintKeyValue("Action", action)
		printer.PrintKeyValue("Resource", resource)
		if result.MatchedPolicy != "" {
			printer.PrintKeyValue("Matched Policy", result.MatchedPolicy)
		}
		if result.MatchedRule != "" {
			printer.PrintKeyValue("Matched Rule", result.MatchedRule)
		}
		printer.PrintKeyValue("Evaluation Time", (time.Duration(result.EvaluationTimeNs) * time.Nanosecond).String())
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printPolicyDetails prints policy details in a formatted way
func printPolicyDetails(printer *cli.Printer, policy *iamsvc.Policy) {
	printer.PrintKeyValue("Name", policy.Name)
	printer.PrintKeyValue("Tenant ID", policy.TenantID)
	if policy.Description != "" {
		printer.PrintKeyValue("Description", policy.Description)
	}
	printer.PrintKeyValue("Priority", fmt.Sprintf("%d", policy.Priority))
	if len(policy.Labels) > 0 {
		printer.PrintKeyValue("Labels", formatAttributes(policy.Labels))
	}
	printer.PrintKeyValue("Created At", formatTimestamp(policy.CreatedAt))
	if policy.UpdatedAt != nil {
		printer.PrintKeyValue("Updated At", formatTimestampPtr(policy.UpdatedAt))
	}
}
