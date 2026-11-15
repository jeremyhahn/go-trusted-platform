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
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// profileRoles maps CLI role labels to the platform.v1 DeviceRole enum.
var profileRoles = map[string]platformv1.DeviceRole{
	"unknown":       platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN,
	"control-plane": platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE,
	"worker":        platformv1.DeviceRole_DEVICE_ROLE_WORKER,
	"server":        platformv1.DeviceRole_DEVICE_ROLE_SERVER,
	"client":        platformv1.DeviceRole_DEVICE_ROLE_CLIENT,
	"workstation":   platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION,
	"edge":          platformv1.DeviceRole_DEVICE_ROLE_EDGE,
	"iot":           platformv1.DeviceRole_DEVICE_ROLE_IOT,
	"gateway":       platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
	"load-balancer": platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
}

// profileFlags holds the shared flags for profile create and update.
type profileFlags struct {
	name       string
	model      string
	role       string
	zone       string
	ekSerial   string
	mac        string
	ekCert     string
	configFile string
	// tlsServerName is the certificate name the attestation collector
	// verifies a node of this profile against (#430).
	tlsServerName string
	// clearTLSServerName blanks the stored tlsServerName on update (#462).
	clearTLSServerName bool
	// diceDeviceID is the hex DICE device identifier (#1699).
	diceDeviceID string
	// goldenFWHash is the hex expected firmware hash, 32 bytes (#1699).
	goldenFWHash string
	// match is the rule set FindMatchingProfile selects the profile by.
	match matchRuleFlags
}

// registerProfileFlags binds the shared profile field flags onto cmd.
func registerProfileFlags(cmd *cobra.Command, pf *profileFlags) {
	cmd.Flags().StringVar(&pf.name, "name", "", "profile name")
	cmd.Flags().StringVar(&pf.model, "model", "", "target device model")
	cmd.Flags().StringVar(&pf.role, "role", "", "device role: control-plane, gateway, worker, server, client, workstation, edge, iot, load-balancer")
	cmd.Flags().StringVar(&pf.zone, "zone", "", "default SDN zone for this profile")
	cmd.Flags().StringVar(&pf.ekSerial, "ek-serial", "", "exact TPM EK certificate serial number for boot-time identity resolution")
	cmd.Flags().StringVar(&pf.mac, "mac", "", "exact MAC address for non-TPM device identification")
	cmd.Flags().StringVar(&pf.ekCert, "ek-cert", "", "prestaged TPM EK certificate: path to a PEM file or an inline PEM string")
	cmd.Flags().StringVar(&pf.configFile, "config-file", "", "path to the device platform config (YAML or JSON)")
	cmd.Flags().StringVar(&pf.tlsServerName, "tls-server-name", "", "certificate name the attestation collector verifies nodes of this profile against (e.g. compute.example.internal); empty means the device's own FQDN")
	cmd.Flags().StringVar(&pf.diceDeviceID, "dice-device-id", "", "hex DICE device identifier (1-64 bytes) the registry resolves this profile by")
	cmd.Flags().StringVar(&pf.goldenFWHash, "golden-fw-hash", "", "hex golden firmware hash (FWHash, 32 bytes) expected of the device")
	registerMatchRuleFlags(cmd, &pf.match)
}

// newProfileCommand creates the profile subcommand group for device
// profile management via the SDK device service.
func newProfileCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Device profile management",
		Long: `Create, update, read, match and delete device profiles on the control plane.

A device profile is the pre-boot record for a node: it binds the device
identity (TPM EK certificate serial, MAC address), the prestaged EK
certificate used for EK-bound config delivery and remote UKI signing,
and the full platform configuration delivered at install time.

Examples:
  # Create a profile with a prestaged hardware EK certificate
  platformctl device profile create \
    --name node-02 \
    --role server \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /path/to/ek-cert.pem \
    --config-file /path/to/platform.yaml

  # Prestage the EK certificate on an existing profile
  platformctl device profile update 123 --ek-cert /path/to/ek-cert.pem

  # Name the certificate the attestation collector verifies workers against,
  # then confirm it
  platformctl device profile update 123 --tls-server-name compute.example.internal
  platformctl device profile get 123 --output json`,
	}

	cmd.AddCommand(NewProfileLookupCommands(getFlags)...)
	cmd.AddCommand(newProfileCreateCommand(getFlags))
	cmd.AddCommand(newProfileUpdateCommand(getFlags))
	cmd.AddCommand(newProfileAssignCommand(getFlags))
	cmd.AddCommand(newProfileUnassignCommand(getFlags))

	return cmd
}

// newProfileCreateCommand creates the profile create subcommand.
func newProfileCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var pf profileFlags

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a device profile",
		Long: `Create a device profile on the control plane.

The --ek-cert flag accepts either a path to a PEM file or an inline PEM
string; the certificate must parse as an X.509 certificate. When set,
the config-delivery resolver cryptographically binds config delivery
and remote UKI signing to the hardware EK the certificate describes.

Examples:
  # Create a minimal profile
  platformctl device profile create --name worker-01 --role client

  # Create a profile with hardware-EK prestage and platform config
  platformctl device profile create \
    --name node-02 \
    --role server \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /path/to/ek-cert.pem \
    --config-file /path/to/platform.yaml`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileCreate(getFlags(), &pf)
		},
	}

	registerProfileFlags(cmd, &pf)

	return cmd
}

// newProfileUpdateCommand creates the profile update subcommand.
func newProfileUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var pf profileFlags

	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a device profile",
		Long: `Update an existing device profile on the control plane.

Only the supplied flags are changed; all other profile fields keep
their current values. This is the operator path for prestaging a
hardware EK certificate on an existing profile so EK-bound config
delivery and remote UKI signing can complete for that node.

Examples:
  # Prestage the hardware EK certificate and identity
  platformctl device profile update 123 \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /path/to/ek-cert.pem

  # Replace the device platform config
  platformctl device profile update 123 --config-file /path/to/platform.yaml

  # Name the certificate the attestation collector verifies nodes of this
  # profile against (fleets whose node certificates carry a role name)
  platformctl device profile update 123 --tls-server-name compute.example.internal

  # Clear it again, so the collector verifies nodes against their own FQDN
  platformctl device profile update 123 --clear-tls-server-name`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidProfileID{ID: args[0]}
			}
			return runProfileUpdate(getFlags(), id, &pf)
		},
	}

	registerProfileFlags(cmd, &pf)
	cmd.Flags().BoolVar(&pf.clearTLSServerName, "clear-tls-server-name", false, "clear the profile's TLS server name so the attestation collector verifies nodes against their own FQDN")
	cmd.MarkFlagsMutuallyExclusive("tls-server-name", "clear-tls-server-name")

	return cmd
}

// runProfileCreate validates the flags and creates the profile via the
// SDK device service.
// newProfileCreateMessage builds the CreateProfile message from the parsed
// flags and the already-resolved role, EK certificate and config.
func newProfileCreateMessage(pf *profileFlags, role platformv1.DeviceRole, ekCertPEM string, configJSON []byte) *platformv1.DeviceProfile {
	return &platformv1.DeviceProfile{
		Name:          pf.name,
		Model:         pf.model,
		Role:          role,
		Zone:          pf.zone,
		EkSerial:      pf.ekSerial,
		MacAddress:    pf.mac,
		EkCert:        ekCertPEM,
		Config:        configJSON,
		TlsServerName: pf.tlsServerName,
		DiceDeviceId:  pf.diceDeviceID,
		GoldenFwHash:  pf.goldenFWHash,
		MatchRules:    applyMatchRuleFlags(nil, &pf.match),
	}
}

func runProfileCreate(flags *cli.CommonFlags, pf *profileFlags) error {
	if pf.name == "" {
		return ErrProfileNameRequired{}
	}
	role, err := resolveProfileRole(pf.role)
	if err != nil {
		return err
	}
	ekCertPEM, err := resolveEKCertPEM(pf.ekCert)
	if err != nil {
		return err
	}
	configJSON, err := loadProfileConfig(pf.configFile)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())

	profile := newProfileCreateMessage(pf, role, ekCertPEM, configJSON)

	created, err := deviceClient.CreateProfile(base.Context(), profile)
	if err != nil {
		return ErrProfileCreateFailed{Cause: err}
	}

	return outputProfile(base, flags, created)
}

// runProfileUpdate fetches the existing profile, applies the supplied
// flags, and updates it via the SDK device service. Unset flags leave
// the corresponding profile fields unchanged.
func runProfileUpdate(flags *cli.CommonFlags, id uint64, pf *profileFlags) error {
	ekCertPEM, err := resolveEKCertPEM(pf.ekCert)
	if err != nil {
		return err
	}
	configJSON, err := loadProfileConfig(pf.configFile)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	ctx := base.Context()

	profile, err := deviceClient.GetProfile(ctx, id)
	if err != nil {
		return ErrProfileGetFailed{ID: id, Cause: err}
	}

	if err := applyProfileUpdateFlags(profile, pf, ekCertPEM, configJSON); err != nil {
		return err
	}

	var opts []device.ProfileUpdateOption
	if pf.clearTLSServerName {
		opts = append(opts, device.WithClearTLSServerName())
	}

	updated, err := deviceClient.UpdateProfile(ctx, profile, opts...)
	if err != nil {
		return ErrProfileUpdateFailed{ID: id, Cause: err}
	}

	return outputProfile(base, flags, updated)
}

// applyProfileUpdateFlags merges the supplied flags onto the fetched
// profile. An unset flag leaves the field as the server returned it, so the
// full-replace UpdateProfile that follows writes back everything the caller
// did not name — including tls_server_name and the read-only pcr_baseline,
// which the server ignores on the way in and restores from its own record.
func applyProfileUpdateFlags(profile *platformv1.DeviceProfile, pf *profileFlags, ekCertPEM string, configJSON []byte) error {
	if pf.name != "" {
		profile.Name = pf.name
	}
	if pf.model != "" {
		profile.Model = pf.model
	}
	if pf.role != "" {
		role, err := resolveProfileRole(pf.role)
		if err != nil {
			return err
		}
		profile.Role = role
	}
	if pf.zone != "" {
		profile.Zone = pf.zone
	}
	if pf.ekSerial != "" {
		profile.EkSerial = pf.ekSerial
	}
	if pf.mac != "" {
		profile.MacAddress = pf.mac
	}
	if ekCertPEM != "" {
		profile.EkCert = ekCertPEM
	}
	if len(configJSON) > 0 {
		profile.Config = configJSON
	}
	if pf.tlsServerName != "" {
		profile.TlsServerName = pf.tlsServerName
	}
	if pf.clearTLSServerName {
		profile.TlsServerName = ""
	}
	if pf.diceDeviceID != "" {
		profile.DiceDeviceId = pf.diceDeviceID
	}
	if pf.goldenFWHash != "" {
		profile.GoldenFwHash = pf.goldenFWHash
	}
	profile.MatchRules = applyMatchRuleFlags(profile.MatchRules, &pf.match)
	return nil
}

// resolveProfileRole maps a role label to the platform.v1 DeviceRole
// enum. An empty label maps to the unspecified role so create requests
// without --role stay valid.
func resolveProfileRole(role string) (platformv1.DeviceRole, error) {
	if role == "" {
		return platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED, nil
	}
	mapped, ok := profileRoles[role]
	if !ok {
		return platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED, ErrProfileInvalidRole{Role: role}
	}
	return mapped, nil
}

// resolveEKCertPEM resolves the --ek-cert flag value: an inline PEM
// string is used verbatim, anything else is treated as a file path. The
// resolved value must parse as a PEM-encoded X.509 certificate. An
// empty flag resolves to "" (no prestage).
func resolveEKCertPEM(value string) (string, error) {
	if value == "" {
		return "", nil
	}

	pemData := value
	if !strings.Contains(value, "-----BEGIN") {
		raw, err := os.ReadFile(value)
		if err != nil {
			return "", ErrProfileEKCertReadFailed{Path: value, Cause: err}
		}
		pemData = string(raw)
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", ErrProfileEKCertInvalid{Reason: "no PEM block found"}
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", ErrProfileEKCertInvalid{Reason: err.Error()}
	}

	return pemData, nil
}

// loadProfileConfig reads the --config-file flag (YAML or JSON) and
// returns its JSON encoding for the pb DeviceProfile config bytes
// field. An empty flag resolves to nil (no config change).
func loadProfileConfig(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrProfileConfigReadFailed{Path: path, Cause: err}
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return nil, ErrProfileConfigParseFailed{Path: path, Cause: err}
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, ErrProfileConfigParseFailed{Path: path, Cause: err}
	}
	return configJSON, nil
}

// outputProfile renders a profile result in the requested output format.
func outputProfile(base *cli.BaseCommand, flags *cli.CommonFlags, profile *platformv1.DeviceProfile) error {
	if flags.OutputFormat == cli.OutputFormatTable {
		printProfileResult(base.Printer(), profile)
		return nil
	}
	return base.Output(buildProfileOutput(profile))
}

// buildProfileOutput creates the JSON/YAML output for profile commands.
// The uint64 profile ID is emitted as a decimal string per the repo-wide
// convention for uint64 IDs on the wire.
func buildProfileOutput(profile *platformv1.DeviceProfile) map[string]interface{} {
	output := map[string]interface{}{
		"id":   strconv.FormatUint(profile.GetId(), 10),
		"name": profile.GetName(),
	}
	if profile.GetModel() != "" {
		output["model"] = profile.GetModel()
	}
	if profile.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
		output["role"] = profileRoleLabel(profile.GetRole())
	}
	if profile.GetZone() != "" {
		output["zone"] = profile.GetZone()
	}
	if profile.GetEkSerial() != "" {
		output["ek_serial"] = profile.GetEkSerial()
	}
	if profile.GetMacAddress() != "" {
		output["mac_address"] = profile.GetMacAddress()
	}
	if profile.GetEkCert() != "" {
		output["ek_cert"] = profile.GetEkCert()
	}
	if len(profile.GetConfig()) > 0 {
		output["config_bytes"] = len(profile.GetConfig())
	}
	if profile.GetTlsServerName() != "" {
		output["tls_server_name"] = profile.GetTlsServerName()
	}
	if profile.GetDiceDeviceId() != "" {
		output["dice_device_id"] = profile.GetDiceDeviceId()
	}
	if profile.GetGoldenFwHash() != "" {
		output["golden_fw_hash"] = profile.GetGoldenFwHash()
	}
	if rules := buildMatchRulesOutput(profile.GetMatchRules()); rules != nil {
		output["match_rules"] = rules
	}
	if baseline := profileBaselineOutput(profile.GetPcrBaseline()); baseline != nil {
		output["pcr_baseline"] = baseline
	}
	output["assigned"] = profile.GetAssigned()
	return output
}

// profileBaselineOutput renders the read-only PCR baseline the server
// reports: hex digests keyed by register index (as strings, matching the
// REST shape), the source, the recording time and the seeding device id as
// a decimal string. Nil when the profile has no baseline.
func profileBaselineOutput(baseline *platformv1.PCRBaseline) map[string]interface{} {
	if baseline == nil {
		return nil
	}
	values := make(map[string]string, len(baseline.GetValues()))
	for idx, digest := range baseline.GetValues() {
		values[strconv.FormatUint(uint64(idx), 10)] = hex.EncodeToString(digest)
	}
	output := map[string]interface{}{
		"values": values,
		"source": baseline.GetSource(),
	}
	if baseline.GetRecordedAt() != nil {
		output["recorded_at"] = baseline.GetRecordedAt().AsTime().UTC().Format(time.RFC3339)
	}
	if baseline.GetRecordedFromDeviceId() != 0 {
		output["recorded_from_device_id"] = strconv.FormatUint(baseline.GetRecordedFromDeviceId(), 10)
	}
	return output
}

// profileBaselineSummary is the one-line table rendering of the baseline:
// source, register count and recording time.
func profileBaselineSummary(baseline *platformv1.PCRBaseline) string {
	summary := baseline.GetSource() + " (" + strconv.Itoa(len(baseline.GetValues())) + " registers"
	if baseline.GetRecordedAt() != nil {
		summary += ", recorded " + baseline.GetRecordedAt().AsTime().UTC().Format(time.RFC3339)
	}
	return summary + ")"
}

// profileRoleLabel maps a DeviceRole enum back to its CLI label.
func profileRoleLabel(role platformv1.DeviceRole) string {
	for label, mapped := range profileRoles {
		if mapped == role {
			return label
		}
	}
	return "unknown"
}

// printProfileResult prints a profile in table format.
func printProfileResult(printer *cli.Printer, profile *platformv1.DeviceProfile) {
	printer.PrintKeyValue("Profile ID", strconv.FormatUint(profile.GetId(), 10))
	printer.PrintKeyValue("Name", profile.GetName())
	if profile.GetModel() != "" {
		printer.PrintKeyValue("Model", profile.GetModel())
	}
	if profile.GetRole() != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
		printer.PrintKeyValue("Role", profileRoleLabel(profile.GetRole()))
	}
	if profile.GetZone() != "" {
		printer.PrintKeyValue("Zone", profile.GetZone())
	}
	if profile.GetEkSerial() != "" {
		printer.PrintKeyValue("EK Serial", profile.GetEkSerial())
	}
	if profile.GetMacAddress() != "" {
		printer.PrintKeyValue("MAC", profile.GetMacAddress())
	}
	if profile.GetEkCert() != "" {
		printer.PrintKeyValue("EK Cert", "prestaged (PEM, "+strconv.Itoa(len(profile.GetEkCert()))+" bytes)")
	}
	if len(profile.GetConfig()) > 0 {
		printer.PrintKeyValue("Config", strconv.Itoa(len(profile.GetConfig()))+" bytes (JSON)")
	}
	if profile.GetTlsServerName() != "" {
		printer.PrintKeyValue("TLS Server Name", profile.GetTlsServerName())
	}
	if rules := matchRulesSummary(profile.GetMatchRules()); rules != "" {
		printer.PrintKeyValue("Match Rules", rules)
	}
	if profile.GetPcrBaseline() != nil {
		printer.PrintKeyValue("PCR Baseline", profileBaselineSummary(profile.GetPcrBaseline()))
	}
	printer.PrintKeyValue("Assigned", strconv.FormatBool(profile.GetAssigned()))
}
