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
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
)

// NewGroupCommand creates the group management command group
func NewGroupCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage groups",
		Long: `Manage groups including creation, listing, and membership control.

Supported operations:
  - create: Create a new group
  - get: Retrieve group details
  - list: List all groups in a tenant
  - update: Update group properties
  - delete: Delete a group
  - add-member: Add a user to a group
  - remove-member: Remove a user from a group`,
	}

	cmd.AddCommand(newGroupCreateCommand(getFlags))
	cmd.AddCommand(newGroupGetCommand(getFlags))
	cmd.AddCommand(newGroupListCommand(getFlags))
	cmd.AddCommand(newGroupUpdateCommand(getFlags))
	cmd.AddCommand(newGroupDeleteCommand(getFlags))
	cmd.AddCommand(newGroupAddMemberCommand(getFlags))
	cmd.AddCommand(newGroupRemoveMemberCommand(getFlags))

	return cmd
}

// newGroupCreateCommand creates the group create subcommand
func newGroupCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var description string

	cmd := &cobra.Command{
		Use:   "create <group-id>",
		Short: "Create a new group",
		Long: `Create a new group within a tenant.

The group ID must be unique within the tenant.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupCreate(flags, tenantID, args[0], name, description)
		},
	}

	cmd.Flags().StringVarP(&tenantID, "tenant", "t", "", "tenant ID (required)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "group display name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "group description")

	if err := cmd.MarkFlagRequired("tenant"); err != nil {
		panic(fmt.Sprintf("failed to mark tenant flag required: %v", err))
	}

	return cmd
}

// newGroupGetCommand creates the group get subcommand
func newGroupGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-id> <group-id>",
		Short: "Get group details",
		Long:  "Retrieve detailed information about a specific group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupGet(flags, args[0], args[1])
		},
	}

	return cmd
}

// newGroupListCommand creates the group list subcommand
func newGroupListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var page uint32
	var pageSize uint32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all groups",
		Long:  "Display a list of all groups within a tenant with pagination support",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupList(flags, tenantID, page, pageSize)
		},
	}

	cmd.Flags().StringVarP(&tenantID, "tenant", "t", "", "tenant ID (required)")
	cmd.Flags().Uint32VarP(&page, "page", "p", 1, "page number")
	cmd.Flags().Uint32VarP(&pageSize, "page-size", "s", 50, "maximum number of groups per page")

	if err := cmd.MarkFlagRequired("tenant"); err != nil {
		panic(fmt.Sprintf("failed to mark tenant flag required: %v", err))
	}

	return cmd
}

// newGroupUpdateCommand creates the group update subcommand
func newGroupUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var description string

	cmd := &cobra.Command{
		Use:   "update <group-id>",
		Short: "Update a group",
		Long:  "Update an existing group's properties",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupUpdate(flags, tenantID, args[0], name, description)
		},
	}

	cmd.Flags().StringVarP(&tenantID, "tenant", "t", "", "tenant ID (required)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "new group display name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "new group description")

	if err := cmd.MarkFlagRequired("tenant"); err != nil {
		panic(fmt.Sprintf("failed to mark tenant flag required: %v", err))
	}

	return cmd
}

// newGroupDeleteCommand creates the group delete subcommand
func newGroupDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <tenant-id> <group-id>",
		Short: "Delete a group",
		Long:  "Delete an existing group from a tenant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupDelete(flags, args[0], args[1])
		},
	}

	return cmd
}

// newGroupAddMemberCommand creates the group add-member subcommand
func newGroupAddMemberCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add-member <tenant-id> <group-id> <user-id>",
		Short: "Add a user to a group",
		Long: `Add an existing user as a member of an existing group.

Examples:
  # Add a user to the developers group
  platformctl iam group add-member my-tenant developers user-123`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupMembership(flags, addGroupMember, args[0], args[1], args[2])
		},
	}

	return cmd
}

// newGroupRemoveMemberCommand creates the group remove-member subcommand
func newGroupRemoveMemberCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-member <tenant-id> <group-id> <user-id>",
		Short: "Remove a user from a group",
		Long: `Remove a user from an existing group's membership.

Examples:
  # Remove a user from the developers group
  platformctl iam group remove-member my-tenant developers user-123`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGroupMembership(flags, removeGroupMember, args[0], args[1], args[2])
		},
	}

	return cmd
}

func runGroupCreate(flags *cli.CommonFlags, tenantID, groupID, name, description string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	group, err := sdkClient.CreateGroupDomain(ctx, tenantID, groupID, name, description)
	if err != nil {
		return &WrappedError{Msg: "failed to create group", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(group)

	case cli.OutputFormatTable:
		if group != nil {
			printer.PrintSuccess(fmt.Sprintf("Group created successfully: %s", group.ID))
			fmt.Println()
			printGroupDetails(printer, group)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runGroupGet(flags *cli.CommonFlags, tenantID, groupID string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if groupID == "" {
		return ErrMissingGroupID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	group, err := sdkClient.GetGroupDomain(ctx, tenantID, groupID)
	if err != nil {
		return &WrappedError{Msg: "failed to get group", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(group)

	case cli.OutputFormatTable:
		if group != nil {
			printGroupDetails(printer, group)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runGroupList(flags *cli.CommonFlags, tenantID string, page, pageSize uint32) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.ListGroupsDomain(ctx, tenantID, page, pageSize)
	if err != nil {
		return &WrappedError{Msg: "failed to list groups", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if len(result.Groups) == 0 {
			printer.PrintInfo("No groups found")
			return nil
		}

		table := cli.NewTableData("Group ID", "Name", "Description", "Members", "Created At")
		for _, group := range result.Groups {
			table.AddRow(
				group.ID,
				group.Name,
				truncateString(group.Description, 40),
				fmt.Sprintf("%d", len(group.Members)),
				formatTimestamp(group.CreatedAt),
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

func runGroupUpdate(flags *cli.CommonFlags, tenantID, groupID, name, description string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if groupID == "" {
		return ErrMissingGroupID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	group, err := sdkClient.UpdateGroupDomain(ctx, tenantID, groupID, name, description)
	if err != nil {
		return &WrappedError{Msg: "failed to update group", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(group)

	case cli.OutputFormatTable:
		if group != nil {
			printer.PrintSuccess(fmt.Sprintf("Group updated successfully: %s", group.ID))
			fmt.Println()
			printGroupDetails(printer, group)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runGroupDelete(flags *cli.CommonFlags, tenantID, groupID string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if groupID == "" {
		return ErrMissingGroupID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.DeleteGroupDomain(ctx, tenantID, groupID)
	if err != nil {
		return &WrappedError{Msg: "failed to delete group", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("Group deleted successfully: %s", groupID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete group: %s", groupID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// groupMembershipChange is one group membership verb: the SDK call it makes
// and the words its output uses.
type groupMembershipChange struct {
	apply   func(c *iamsvc.Client, ctx context.Context, tenantID, groupID, userID string) error
	failure string
	success string
}

var (
	addGroupMember = groupMembershipChange{
		apply:   (*iamsvc.Client).AddGroupMember,
		failure: "failed to add user to group",
		success: "User %s added to group %s",
	}
	removeGroupMember = groupMembershipChange{
		apply:   (*iamsvc.Client).RemoveGroupMember,
		failure: "failed to remove user from group",
		success: "User %s removed from group %s",
	}
)

// runGroupMembership adds a user to, or removes one from, a group.
func runGroupMembership(flags *cli.CommonFlags, change groupMembershipChange, tenantID, groupID, userID string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if groupID == "" {
		return ErrMissingGroupID{}
	}
	if userID == "" {
		return ErrMissingUserID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	if err := change.apply(sdkClient, base.Context(), tenantID, groupID, userID); err != nil {
		return &WrappedError{Msg: change.failure, Err: err}
	}

	message := fmt.Sprintf(change.success, userID, groupID)
	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(&iamsvc.OperationStatus{Success: true, Message: message})

	case cli.OutputFormatTable:
		printer.PrintSuccess(message)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printGroupDetails prints detailed information about a group
func printGroupDetails(printer *cli.Printer, group *iamsvc.Group) {
	printer.PrintKeyValue("Group ID", group.ID)
	printer.PrintKeyValue("Tenant ID", group.TenantID)
	if group.Name != "" {
		printer.PrintKeyValue("Name", group.Name)
	}
	if group.Description != "" {
		printer.PrintKeyValue("Description", group.Description)
	}
	if len(group.Members) > 0 {
		printer.PrintKeyValue("Members", strings.Join(group.Members, ", "))
	} else {
		printer.PrintKeyValue("Members", "(none)")
	}
	printer.PrintKeyValue("Created At", formatTimestamp(group.CreatedAt))
	if group.UpdatedAt != nil {
		printer.PrintKeyValue("Updated At", formatTimestampPtr(group.UpdatedAt))
	}
}
