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

package device

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// templateFlags are the template fields the create and update verbs set.
type templateFlags struct {
	name        string
	description string
	role        string
	configFile  string
	match       matchRuleFlags
}

func registerTemplateFlags(cmd *cobra.Command, tf *templateFlags) {
	cmd.Flags().StringVar(&tf.name, "name", "", "template name")
	cmd.Flags().StringVar(&tf.description, "description", "", "template description")
	cmd.Flags().StringVar(&tf.role, "role", "", "device role: control-plane, gateway, worker, server, client, workstation, edge, iot, load-balancer")
	cmd.Flags().StringVar(&tf.configFile, "config-file", "", "path to the device platform config (YAML or JSON) every profile built from the template starts from")
	registerMatchRuleFlags(cmd, &tf.match)
}

// newTemplateCommand creates the device template command group.
func newTemplateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage device templates",
		Long: `Manage device templates.

A template is a reusable profile blueprint: a role, a platform config and a
match-rule set. 'template create-profile' builds a device profile from one,
with the identity binding and any other overrides the command is given.
Deleting a template does not affect the profiles built from it.`,
	}
	cmd.AddCommand(
		newTemplateCreateCommand(getFlags),
		newTemplateGetCommand(getFlags),
		newTemplateListCommand(getFlags),
		newTemplateUpdateCommand(getFlags),
		newTemplateDeleteCommand(getFlags),
		newTemplateCreateProfileCommand(getFlags),
	)
	return cmd
}

// runWithDeviceClient connects through the selected context and runs fn
// with the device client and the output printer.
func runWithDeviceClient(flags *cli.CommonFlags, fn func(ctx context.Context, client *device.Client, printer *cli.Printer) error) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()
	return fn(base.Context(), device.NewClientFromGRPC(base.Client().Device()), base.Printer())
}

func parseTemplateID(value string) (uint64, error) {
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrInvalidTemplateID{ID: value}
	}
	return id, nil
}

// templateFailure maps a control-plane error to the CLI's typed error: a
// not-found answer for a known id is ErrTemplateNotFound.
func templateFailure(operation string, id uint64, err error) error {
	if id != 0 && isNotFound(err) {
		return ErrTemplateNotFound{ID: id}
	}
	return ErrTemplateOperationFailed{Operation: operation, ID: id, Cause: err}
}

func newTemplateCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tf templateFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a device template",
		Long: `Create a device template and print it with its assigned id.

Examples:
  platformctl device template create --name rack-server --role server \
    --config-file server.yaml --match-serial-prefix SN-R650-`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			template, err := buildTemplate(&tf)
			if err != nil {
				return err
			}
			flags := getFlags()
			return runWithDeviceClient(flags, func(ctx context.Context, client *device.Client, printer *cli.Printer) error {
				return createTemplateAndPrint(ctx, client, printer, flags.OutputFormat, template)
			})
		},
	}
	registerTemplateFlags(cmd, &tf)
	return cmd
}

// buildTemplate validates the create flags and builds the template to
// store; it runs before any connection is attempted.
func buildTemplate(tf *templateFlags) (*platformv1.DeviceTemplate, error) {
	if tf.name == "" {
		return nil, ErrTemplateNameRequired{}
	}
	role, err := resolveProfileRole(tf.role)
	if err != nil {
		return nil, err
	}
	config, err := loadProfileConfig(tf.configFile)
	if err != nil {
		return nil, err
	}
	return &platformv1.DeviceTemplate{
		Name:        tf.name,
		Description: tf.description,
		Role:        role,
		Config:      config,
		MatchRules:  applyMatchRuleFlags(nil, &tf.match),
	}, nil
}

func createTemplateAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, template *platformv1.DeviceTemplate) error {
	created, err := client.CreateTemplate(ctx, template)
	if err != nil {
		return templateFailure("create", 0, err)
	}
	return printTemplate(printer, format, created)
}

func newTemplateGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show a device template",
		Long: `Show a device template by id.

Examples:
  platformctl device template get 1234567890 --output json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseTemplateID(args[0])
			if err != nil {
				return err
			}
			flags := getFlags()
			return runWithDeviceClient(flags, func(ctx context.Context, client *device.Client, printer *cli.Printer) error {
				return getTemplateAndPrint(ctx, client, printer, flags.OutputFormat, id)
			})
		},
	}
}

func getTemplateAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, id uint64) error {
	template, err := client.GetTemplate(ctx, id)
	if err != nil {
		return templateFailure("get", id, err)
	}
	if template == nil {
		return ErrTemplateNotFound{ID: id}
	}
	return printTemplate(printer, format, template)
}

func newTemplateListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var page, pageSize int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List device templates",
		Long: `List device templates with their id, name, role, description and match rules.

Examples:
  platformctl device template list
  platformctl device template list --page 2 --page-size 50 --output json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if page < 1 || pageSize < 1 {
				return ErrInvalidPagination{Page: page, PageSize: pageSize}
			}
			flags := getFlags()
			return runWithDeviceClient(flags, func(ctx context.Context, client *device.Client, printer *cli.Printer) error {
				return listTemplatesAndPrint(ctx, client, printer, flags.OutputFormat, page, pageSize)
			})
		},
	}
	cmd.Flags().IntVar(&page, "page", 1, "page number (1-based)")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "templates per page")
	return cmd
}

func listTemplatesAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, page, pageSize int) error {
	templates, pageResult, err := client.ListTemplates(ctx, common.NewPagination(uint32(page), uint32(pageSize)))
	if err != nil {
		return templateFailure("list", 0, err)
	}
	var total int
	if pageResult != nil {
		total = int(pageResult.TotalItems)
	}
	if format == cli.OutputFormatTable {
		return printTemplateListTable(printer, templates, page, pageSize, total)
	}
	return printer.Print(buildTemplateListOutput(page, pageSize, total, templates))
}

func newTemplateUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tf templateFlags
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a device template",
		Long: `Update a device template. The command reads the template, changes only the
fields whose flags are given, and stores it; every other field keeps its
value. Profiles already built from the template are not changed.

Examples:
  platformctl device template update 1234567890 --description "R650 rack servers"
  platformctl device template update 1234567890 --role edge --match-mac-prefix 52:54:00`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseTemplateID(args[0])
			if err != nil {
				return err
			}
			// Resolve the role and read the config before connecting, so a
			// bad flag fails without a round trip.
			if _, err := resolveProfileRole(tf.role); err != nil {
				return err
			}
			config, err := loadProfileConfig(tf.configFile)
			if err != nil {
				return err
			}
			flags := getFlags()
			return runWithDeviceClient(flags, func(ctx context.Context, client *device.Client, printer *cli.Printer) error {
				return updateTemplateAndPrint(ctx, client, printer, flags.OutputFormat, id, &tf, config)
			})
		},
	}
	registerTemplateFlags(cmd, &tf)
	return cmd
}

// updateTemplateAndPrint reads template id, applies the flags and stores
// it. UpdateTemplate replaces every field, so the read is what keeps the
// fields the flags do not name.
func updateTemplateAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, id uint64, tf *templateFlags, config []byte) error {
	template, err := client.GetTemplate(ctx, id)
	if err != nil {
		return templateFailure("get", id, err)
	}
	if template == nil {
		return ErrTemplateNotFound{ID: id}
	}
	if err := applyTemplateUpdateFlags(template, tf, config); err != nil {
		return err
	}
	updated, err := client.UpdateTemplate(ctx, template)
	if err != nil {
		return templateFailure("update", id, err)
	}
	return printTemplate(printer, format, updated)
}

// applyTemplateUpdateFlags sets each field whose flag was given and leaves
// the rest.
func applyTemplateUpdateFlags(template *platformv1.DeviceTemplate, tf *templateFlags, config []byte) error {
	if tf.name != "" {
		template.Name = tf.name
	}
	if tf.description != "" {
		template.Description = tf.description
	}
	if tf.role != "" {
		role, err := resolveProfileRole(tf.role)
		if err != nil {
			return err
		}
		template.Role = role
	}
	if len(config) > 0 {
		template.Config = config
	}
	template.MatchRules = applyMatchRuleFlags(template.MatchRules, &tf.match)
	return nil
}

func newTemplateDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a device template",
		Long: `Delete a device template. Profiles already built from it are not affected.

Examples:
  platformctl device template delete 1234567890`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseTemplateID(args[0])
			if err != nil {
				return err
			}
			flags := getFlags()
			return runWithDeviceClient(flags, func(ctx context.Context, client *device.Client, printer *cli.Printer) error {
				return deleteTemplateAndPrint(ctx, client, printer, flags.OutputFormat, id)
			})
		},
	}
}

func deleteTemplateAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, id uint64) error {
	if err := client.DeleteTemplate(ctx, id); err != nil {
		return templateFailure("delete", id, err)
	}
	if format == cli.OutputFormatTable {
		printer.PrintSuccess("Template " + strconv.FormatUint(id, 10) + " deleted")
		return nil
	}
	return printer.Print(map[string]interface{}{
		"id":      strconv.FormatUint(id, 10),
		"deleted": true,
	})
}

func newTemplateCreateProfileCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var pf profileFlags
	cmd := &cobra.Command{
		Use:   "create-profile <template-id>",
		Short: "Create a device profile from a template",
		Long: `Create a device profile from a template. The profile starts from the
template's role, platform config and match rules; each flag given overrides
the template's value or sets the profile's identity binding.

Examples:
  platformctl device template create-profile 1234567890 --name r650-01 --ek-serial 0A1B2C
  platformctl device template create-profile 1234567890 --name kiosk-07 --mac 52:54:00:12:34:56`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseTemplateID(args[0])
			if err != nil {
				return err
			}
			overrides, err := buildProfileOverrides(&pf)
			if err != nil {
				return err
			}
			flags := getFlags()
			return runWithDeviceClient(flags, func(ctx context.Context, client *device.Client, printer *cli.Printer) error {
				return createProfileFromTemplateAndPrint(ctx, client, printer, flags.OutputFormat, id, overrides)
			})
		},
	}
	cmd.Flags().StringVar(&pf.name, "name", "", "profile name")
	cmd.Flags().StringVar(&pf.model, "model", "", "target device model")
	cmd.Flags().StringVar(&pf.role, "role", "", "device role, overriding the template's")
	cmd.Flags().StringVar(&pf.zone, "zone", "", "default SDN zone for this profile")
	cmd.Flags().StringVar(&pf.ekSerial, "ek-serial", "", "exact TPM EK certificate serial number for boot-time identity resolution")
	cmd.Flags().StringVar(&pf.mac, "mac", "", "exact MAC address for non-TPM device identification")
	cmd.Flags().StringVar(&pf.ekCert, "ek-cert", "", "prestaged TPM EK certificate: path to a PEM file or an inline PEM string")
	registerMatchRuleFlags(cmd, &pf.match)
	return cmd
}

// buildProfileOverrides is the override profile of create-profile: only
// the fields whose flags were given are set, and the server keeps the
// template's value for every other field.
func buildProfileOverrides(pf *profileFlags) (*platformv1.DeviceProfile, error) {
	role, err := resolveProfileRole(pf.role)
	if err != nil {
		return nil, err
	}
	ekCertPEM, err := resolveEKCertPEM(pf.ekCert)
	if err != nil {
		return nil, err
	}
	return &platformv1.DeviceProfile{
		Name:       pf.name,
		Model:      pf.model,
		Role:       role,
		Zone:       pf.zone,
		EkSerial:   pf.ekSerial,
		MacAddress: pf.mac,
		EkCert:     ekCertPEM,
		MatchRules: applyMatchRuleFlags(nil, &pf.match),
	}, nil
}

func createProfileFromTemplateAndPrint(ctx context.Context, client *device.Client, printer *cli.Printer, format cli.OutputFormat, templateID uint64, overrides *platformv1.DeviceProfile) error {
	profile, err := client.CreateProfileFromTemplate(ctx, templateID, overrides)
	if err != nil {
		return templateFailure("create-profile", templateID, err)
	}
	if format == cli.OutputFormatTable {
		printProfileResult(printer, profile)
		return nil
	}
	return printer.Print(buildProfileOutput(profile))
}

func printTemplate(printer *cli.Printer, format cli.OutputFormat, template *platformv1.DeviceTemplate) error {
	if format == cli.OutputFormatTable {
		printTemplateResult(printer, template)
		return nil
	}
	return printer.Print(buildTemplateOutput(template))
}

// buildTemplateOutput is the JSON and YAML shape of a template; the id is
// a decimal string, as for profiles.
func buildTemplateOutput(template *platformv1.DeviceTemplate) map[string]interface{} {
	output := map[string]interface{}{
		"id":   strconv.FormatUint(template.GetId(), 10),
		"name": template.GetName(),
	}
	if template.GetDescription() != "" {
		output["description"] = template.GetDescription()
	}
	if template.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
		output["role"] = profileRoleLabel(template.GetRole())
	}
	if len(template.GetConfig()) > 0 {
		output["config_bytes"] = len(template.GetConfig())
	}
	if rules := buildMatchRulesOutput(template.GetMatchRules()); rules != nil {
		output["match_rules"] = rules
	}
	return output
}

func printTemplateResult(printer *cli.Printer, template *platformv1.DeviceTemplate) {
	printer.PrintKeyValue("Template ID", strconv.FormatUint(template.GetId(), 10))
	printer.PrintKeyValue("Name", template.GetName())
	if template.GetDescription() != "" {
		printer.PrintKeyValue("Description", template.GetDescription())
	}
	if template.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
		printer.PrintKeyValue("Role", profileRoleLabel(template.GetRole()))
	}
	if len(template.GetConfig()) > 0 {
		printer.PrintKeyValue("Config", strconv.Itoa(len(template.GetConfig()))+" bytes")
	}
	if rules := matchRulesSummary(template.GetMatchRules()); rules != "" {
		printer.PrintKeyValue("Match Rules", rules)
	}
}

func buildTemplateListOutput(page, pageSize, total int, templates []*platformv1.DeviceTemplate) map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(templates))
	for _, template := range templates {
		items = append(items, buildTemplateOutput(template))
	}
	return map[string]interface{}{
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": (total + pageSize - 1) / pageSize,
		"templates":   items,
	}
}

func printTemplateListTable(printer *cli.Printer, templates []*platformv1.DeviceTemplate, page, pageSize, total int) error {
	if len(templates) == 0 {
		printer.PrintInfo("No templates found")
		return nil
	}
	table := cli.NewTableData("ID", "NAME", "ROLE", "DESCRIPTION", "MATCH RULES")
	for _, template := range templates {
		role := ""
		if template.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
			role = profileRoleLabel(template.GetRole())
		}
		table.AddRow(
			strconv.FormatUint(template.GetId(), 10),
			truncate(template.GetName(), 30),
			role,
			truncate(template.GetDescription(), 40),
			truncate(matchRulesSummary(template.GetMatchRules()), 40),
		)
	}
	if err := printer.Print(*table); err != nil {
		return err
	}
	printer.PrintInfo(fmt.Sprintf("Page %d of %d (Total: %d templates)", page, (total+pageSize-1)/pageSize, total))
	return nil
}
