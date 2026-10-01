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
	"net"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// validRoles defines the accepted device role labels for registration.
var validRoles = map[string]platformv1.DeviceRole{
	"control-plane": platformv1.DeviceRole_DEVICE_ROLE_SERVER,
	"gateway":       platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
	"worker":        platformv1.DeviceRole_DEVICE_ROLE_CLIENT,
}

// registerFlags holds the flags for the device register command.
type registerFlags struct {
	hostname     string
	mac          string
	role         string
	template     string
	overrideFile string
	server       string
	caCert       string
}

// newRegisterCommand creates the register subcommand for registering a device
// with the control plane.
func newRegisterCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var rf registerFlags

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a device with the control plane",
		Long: `Register a new device with the platform control plane.

The register command creates a device profile on the control plane
with the specified hostname, MAC address, role, and template name.
An optional YAML override file can supply additional configuration
that is stored in the profile event_log field as serialized config.

The --server flag specifies the control plane URL. When the CP uses a
private CA, supply --ca-cert with the path to the CA certificate PEM
for TLS verification.

Roles:
  control-plane  Control plane node
  gateway        Gateway / edge node
  worker         Compute worker node

Examples:
  # Register a gateway device
  platformctl device register \
    --hostname gw-01 \
    --mac 00:25:90:FF:AA:01 \
    --role gateway \
    --template gateway-default \
    --server https://10.4.2.140:8443

  # Register with a private CA and config overrides
  platformctl device register \
    --hostname worker-03 \
    --mac 00:25:90:FF:BB:03 \
    --role worker \
    --template worker-default \
    --override-file /etc/platform/overrides.yaml \
    --server https://cp.example.com:8443 \
    --ca-cert /etc/platform/ca.pem`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRegister(flags, &rf)
		},
	}

	cmd.Flags().StringVar(&rf.hostname, "hostname", "", "device hostname (required)")
	cmd.Flags().StringVar(&rf.mac, "mac", "", "device MAC address (required)")
	cmd.Flags().StringVar(&rf.role, "role", "", "device role: control-plane, gateway, worker (required)")
	cmd.Flags().StringVar(&rf.template, "template", "", "template name for the device profile (required)")
	cmd.Flags().StringVar(&rf.overrideFile, "override-file", "", "path to YAML override file (optional)")
	cmd.Flags().StringVar(&rf.server, "server", "", "control plane URL, e.g. https://10.4.2.140:8443 (required)")
	cmd.Flags().StringVar(&rf.caCert, "ca-cert", "", "path to CA certificate PEM for TLS verification (optional)")

	return cmd
}

// runRegister validates inputs, connects to the control plane, and creates
// a device profile with the specified parameters.
func runRegister(flags *cli.CommonFlags, rf *registerFlags) error {
	if err := validateRegisterFlags(rf); err != nil {
		return err
	}

	// Read and validate override config if provided
	var overrideBytes []byte
	if rf.overrideFile != "" {
		raw, err := os.ReadFile(rf.overrideFile)
		if err != nil {
			return ErrRegisterReadOverrideFile{Path: rf.overrideFile, Cause: err}
		}
		var probe map[string]interface{}
		if err := yaml.Unmarshal(raw, &probe); err != nil {
			return ErrRegisterParseOverrideFile{Path: rf.overrideFile, Cause: err}
		}
		overrideBytes = raw
	}

	// Build a CLI context that targets the CP server. The register command
	// constructs its own ad-hoc remote context instead of relying on the
	// user's saved platformctl context, because the device being registered
	// may not have a context configured yet.
	overrideGetContext := buildRegisterContext(rf)
	registerFlags := &cli.CommonFlags{
		ConfigPath:   flags.ConfigPath,
		ContextName:  flags.ContextName,
		OutputFormat: flags.OutputFormat,
		Verbose:      flags.Verbose,
		NoColor:      flags.NoColor,
		GetConfig:    flags.GetConfig,
		GetContext:   overrideGetContext,
	}

	base, err := cli.NewBaseCommand(registerFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	ctx := base.Context()
	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	// Build the device profile from flags and override file.
	// The template name, role string, hostname, and MAC are stored in
	// match_rules custom_attributes for downstream consumers. Override
	// config bytes are stored in event_log until the proto is regenerated
	// with a dedicated config field.
	protoRole := validRoles[rf.role]
	profile := &platformv1.DeviceProfile{
		Name: rf.hostname,
		Role: protoRole,
		MatchRules: &platformv1.ProfileMatchRules{
			CustomAttributes: map[string]string{
				"role":        rf.role,
				"hostname":    rf.hostname,
				"mac_address": rf.mac,
				"template":    rf.template,
			},
		},
	}
	if len(overrideBytes) > 0 {
		profile.EventLog = overrideBytes
	}

	// Create the profile on the control plane
	created, err := deviceClient.CreateProfile(ctx, profile)
	if err != nil {
		return ErrRegisterCreateProfileFailed{Cause: err}
	}

	// Output the result
	result := buildRegisterOutput(created, rf)

	if flags.OutputFormat == cli.OutputFormatTable {
		printRegisterResult(base.Printer(), created, rf)
		return nil
	}

	return base.Output(result)
}

// validateRegisterFlags validates all required register flags.
func validateRegisterFlags(rf *registerFlags) error {
	if rf.hostname == "" {
		return ErrRegisterHostnameRequired{}
	}
	if rf.mac == "" {
		return ErrRegisterMACRequired{}
	}
	if _, err := net.ParseMAC(rf.mac); err != nil {
		return ErrRegisterInvalidMACAddress{MAC: rf.mac}
	}
	if rf.role == "" {
		return ErrRegisterRoleRequired{}
	}
	if _, ok := validRoles[rf.role]; !ok {
		return ErrRegisterInvalidRole{Role: rf.role}
	}
	if rf.template == "" {
		return ErrRegisterTemplateRequired{}
	}
	if rf.server == "" {
		return ErrRegisterServerRequired{}
	}
	return nil
}

// buildRegisterContext returns a GetContext function that produces an ad-hoc
// remote context pointing at the control plane server via REST, optionally
// configured with a custom CA certificate for TLS verification.
func buildRegisterContext(rf *registerFlags) func() (*cli.Context, error) {
	return func() (*cli.Context, error) {
		ctx := &cli.Context{
			Name:     "register",
			Type:     cli.ContextTypeRemote,
			Protocol: "rest",
			Remote: &cli.RemoteContext{
				Server: rf.server,
			},
		}

		if rf.caCert != "" {
			ctx.Remote.CACert = rf.caCert
		}

		return ctx, nil
	}
}

// buildRegisterOutput creates the JSON/YAML output for the register command.
func buildRegisterOutput(profile *platformv1.DeviceProfile, rf *registerFlags) map[string]interface{} {
	return map[string]interface{}{
		"profile_id": profile.Id,
		"hostname":   rf.hostname,
		"mac":        rf.mac,
		"role":       rf.role,
		"template":   rf.template,
		"name":       profile.Name,
	}
}

// printRegisterResult prints the registration result in table format.
func printRegisterResult(printer *cli.Printer, profile *platformv1.DeviceProfile, rf *registerFlags) {
	printer.PrintKeyValue("Profile ID", strconv.FormatUint(profile.Id, 10))
	printer.PrintKeyValue("Hostname", rf.hostname)
	printer.PrintKeyValue("MAC", rf.mac)
	printer.PrintKeyValue("Role", rf.role)
	printer.PrintKeyValue("Template", rf.template)
	printer.PrintKeyValue("Profile Name", profile.Name)
}
