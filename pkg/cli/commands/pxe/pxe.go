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

// Package pxe implements the "platformctl pxe" command group, which drives
// the PXE provisioning workflow through the platform's PXEService.
package pxe

import (
	"context"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// defaultCLITimeout bounds every RPC a command makes.
const defaultCLITimeout = 30 * time.Second

// statePrefix is the prefix every ProvisioningState value name carries.
const statePrefix = "PROVISIONING_STATE_"

// eventPrefix is the prefix every ProvisioningEventType value name carries.
const eventPrefix = "PROVISIONING_EVENT_TYPE_"

// clientFactory opens a PXE service client from the common flags and
// returns it with the function that closes the connection. Tests replace
// it with a fake.
type clientFactory func(flags *cli.CommonFlags) (platformv1.PXEServiceClient, func() error, error)

// sdkClient is the production factory: it honours the global transport
// flags through cli.NewBaseCommand and returns platform.Client.PXE().
func sdkClient(flags *cli.CommonFlags) (platformv1.PXEServiceClient, func() error, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	return platform.Client.PXE(base.Client()), base.Close, nil
}

// NewCommand creates the "pxe" command group.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return newCommandWith(getFlags, sdkClient)
}

// newCommandWith builds the group on the given client factory.
func newCommandWith(getFlags func() *cli.CommonFlags, open clientFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pxe",
		Short: "PXE provisioning workflow",
		Long: `Inspect and drive devices through the PXE provisioning workflow.

Devices are discovered when they PXE boot, install, enroll, and are then
authorized onto their target VLAN or quarantined.

Examples:
  # List devices waiting in the quarantine VLAN
  platformctl pxe list --state quarantined

  # Show one device and its provisioning events
  platformctl pxe get <device-id>
  platformctl pxe events <device-id>

  # Move an enrolled device onto VLAN 20
  platformctl pxe authorize <device-id> --target-vlan 20

  # Quarantine a device, recording why
  platformctl pxe quarantine <device-id> --reason "attestation mismatch"

  # Send a failed device back through provisioning
  platformctl pxe retry <device-id>`,
	}

	r := &runner{getFlags: getFlags, open: open}
	cmd.AddCommand(r.listCommand())
	cmd.AddCommand(r.getCommand())
	cmd.AddCommand(r.authorizeCommand())
	cmd.AddCommand(r.quarantineCommand())
	cmd.AddCommand(r.retryCommand())
	cmd.AddCommand(r.eventsCommand())
	return cmd
}

// runner carries what every verb needs: the flags and the client factory.
type runner struct {
	getFlags func() *cli.CommonFlags
	open     clientFactory
}

// call opens a client, runs fn under the CLI timeout and prints the value it
// returns: the table for table output, the reply itself otherwise.
func (r *runner) call(cmd *cobra.Command, rpc string,
	fn func(context.Context, platformv1.PXEServiceClient) (reply any, table *cli.TableData, err error)) error {
	flags := r.getFlags()
	client, closeFn, err := r.open(flags)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()

	ctx, cancel := context.WithTimeout(context.Background(), defaultCLITimeout)
	defer cancel()

	reply, table, err := fn(ctx, client)
	if err != nil {
		return &ErrRPCFailed{RPC: rpc, Cause: err}
	}
	return render(cmd.OutOrStdout(), flags, reply, table)
}

// render prints reply as JSON or YAML when asked for, the table otherwise.
func render(w io.Writer, flags *cli.CommonFlags, reply any, table *cli.TableData) error {
	printer := cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, w)
	if flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML {
		return printer.Print(reply)
	}
	return printer.Print(table)
}

// deviceArg returns the single positional device ID, refusing an empty one.
func deviceArg(verb string, args []string) (string, error) {
	id := strings.TrimSpace(args[0])
	if id == "" {
		return "", &ErrDeviceIDRequired{Verb: verb}
	}
	return id, nil
}

func (r *runner) listCommand() *cobra.Command {
	var (
		state  string
		mac    string
		vlan   uint32
		limit  int32
		offset int32
	)
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List devices in the provisioning workflow",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			filter := &platformv1.PXEDeviceFilter{MacAddress: mac, Vlan: vlan, Limit: limit, Offset: offset}
			if state != "" {
				parsed, err := parseState(state)
				if err != nil {
					return err
				}
				filter.State = parsed
			}
			return r.call(cmd, "ListDevices", func(ctx context.Context, c platformv1.PXEServiceClient) (any, *cli.TableData, error) {
				resp, err := c.ListDevices(ctx, &platformv1.ListPXEDevicesRequest{Filter: filter})
				if err != nil {
					return nil, nil, err
				}
				return resp, devicesTable(resp.GetDevices()...), nil
			})
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "filter by state ("+strings.Join(stateLabels(), ", ")+")")
	cmd.Flags().StringVar(&mac, "mac", "", "filter by MAC address (exact or prefix)")
	cmd.Flags().Uint32Var(&vlan, "vlan", 0, "filter by current VLAN")
	cmd.Flags().Int32Var(&limit, "limit", 0, "maximum number of devices (0 for the server default)")
	cmd.Flags().Int32Var(&offset, "offset", 0, "number of devices to skip")
	return cmd
}

func (r *runner) getCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "get <device-id>",
		Short:        "Show one device",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := deviceArg("get", args)
			if err != nil {
				return err
			}
			return r.call(cmd, "GetDevice", func(ctx context.Context, c platformv1.PXEServiceClient) (any, *cli.TableData, error) {
				resp, err := c.GetDevice(ctx, &platformv1.GetPXEDeviceRequest{DeviceId: id})
				if err != nil {
					return nil, nil, err
				}
				return resp, deviceTable(resp.GetDevice()), nil
			})
		},
	}
}

func (r *runner) authorizeCommand() *cobra.Command {
	var targetVLAN uint32
	cmd := &cobra.Command{
		Use:          "authorize <device-id>",
		Short:        "Authorize a device onto its target VLAN",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := deviceArg("authorize", args)
			if err != nil {
				return err
			}
			return r.call(cmd, "Authorize", func(ctx context.Context, c platformv1.PXEServiceClient) (any, *cli.TableData, error) {
				resp, err := c.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{DeviceId: id, TargetVlan: targetVLAN})
				if err != nil {
					return nil, nil, err
				}
				return resp, deviceTable(resp.GetDevice()), nil
			})
		},
	}
	cmd.Flags().Uint32Var(&targetVLAN, "target-vlan", 0, "VLAN to move the device to (0 for the one its profile names)")
	return cmd
}

func (r *runner) quarantineCommand() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:          "quarantine <device-id>",
		Short:        "Quarantine a device",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := deviceArg("quarantine", args)
			if err != nil {
				return err
			}
			if strings.TrimSpace(reason) == "" {
				return &ErrReasonRequired{}
			}
			return r.call(cmd, "Quarantine", func(ctx context.Context, c platformv1.PXEServiceClient) (any, *cli.TableData, error) {
				resp, err := c.Quarantine(ctx, &platformv1.QuarantinePXEDeviceRequest{DeviceId: id, Reason: reason})
				if err != nil {
					return nil, nil, err
				}
				return resp, deviceTable(resp.GetDevice()), nil
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why the device is quarantined (required)")
	return cmd
}

func (r *runner) retryCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "retry <device-id>",
		Short:        "Send a failed or quarantined device back through provisioning",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := deviceArg("retry", args)
			if err != nil {
				return err
			}
			return r.call(cmd, "Retry", func(ctx context.Context, c platformv1.PXEServiceClient) (any, *cli.TableData, error) {
				resp, err := c.Retry(ctx, &platformv1.RetryPXEDeviceRequest{DeviceId: id})
				if err != nil {
					return nil, nil, err
				}
				return resp, deviceTable(resp.GetDevice()), nil
			})
		},
	}
}

func (r *runner) eventsCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "events <device-id>",
		Short:        "Show the provisioning events of a device",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := deviceArg("events", args)
			if err != nil {
				return err
			}
			return r.call(cmd, "GetEvents", func(ctx context.Context, c platformv1.PXEServiceClient) (any, *cli.TableData, error) {
				resp, err := c.GetEvents(ctx, &platformv1.GetPXEEventsRequest{DeviceId: id})
				if err != nil {
					return nil, nil, err
				}
				return resp, eventsTable(resp.GetEvents()), nil
			})
		},
	}
}

// devicesTable renders one row per device.
func devicesTable(devices ...*platformv1.PXEDeviceInfo) *cli.TableData {
	table := cli.NewTableData("ID", "MAC", "STATE", "VLAN", "TARGET VLAN", "RETRIES", "UPDATED")
	for _, d := range devices {
		table.AddRow(d.GetId(), d.GetMacAddress(), stateLabel(d.GetState()),
			vlanLabel(d.GetCurrentVlan()), vlanLabel(d.GetTargetVlan()),
			strconv.Itoa(int(d.GetRetryCount())), timeLabel(d.GetUpdatedAt()))
	}
	return table
}

// deviceTable renders one device as a FIELD/VALUE table.
func deviceTable(d *platformv1.PXEDeviceInfo) *cli.TableData {
	table := cli.NewTableData("FIELD", "VALUE")
	if d == nil {
		return table
	}
	table.AddRow("id", d.GetId())
	table.AddRow("mac address", d.GetMacAddress())
	table.AddRow("port id", d.GetPortId())
	table.AddRow("state", stateLabel(d.GetState()))
	table.AddRow("state reason", d.GetStateReason())
	table.AddRow("profile", d.GetProfile().GetName())
	table.AddRow("certificate serial", d.GetCertificateSerial())
	table.AddRow("current vlan", vlanLabel(d.GetCurrentVlan()))
	table.AddRow("target vlan", vlanLabel(d.GetTargetVlan()))
	table.AddRow("retries", strconv.Itoa(int(d.GetRetryCount())))
	table.AddRow("created", timeLabel(d.GetCreatedAt()))
	table.AddRow("updated", timeLabel(d.GetUpdatedAt()))
	table.AddRow("state changed", timeLabel(d.GetStateChangedAt()))
	return table
}

// eventsTable renders one row per provisioning event.
func eventsTable(events []*platformv1.ProvisioningEvent) *cli.TableData {
	table := cli.NewTableData("TIME", "ID", "EVENT", "FROM", "TO", "DETAILS", "ERROR")
	for _, e := range events {
		table.AddRow(timeLabel(e.GetTimestamp()), e.GetId(), eventLabel(e.GetEventType()),
			stateLabel(e.GetFromState()), stateLabel(e.GetToState()),
			detailsLabel(e.GetDetails()), e.GetError())
	}
	return table
}

// stateLabel is the CLI spelling of a state: PROVISIONING_STATE_INSTALL_COMPLETE
// prints as install-complete. A value newer than this client prints as its
// number.
func stateLabel(s platformv1.ProvisioningState) string {
	name, ok := platformv1.ProvisioningState_name[int32(s)]
	if !ok {
		return strconv.Itoa(int(s))
	}
	return kebab(strings.TrimPrefix(name, statePrefix))
}

// eventLabel is the CLI spelling of an event type.
func eventLabel(t platformv1.ProvisioningEventType) string {
	name, ok := platformv1.ProvisioningEventType_name[int32(t)]
	if !ok {
		return strconv.Itoa(int(t))
	}
	return kebab(strings.TrimPrefix(name, eventPrefix))
}

func kebab(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// stateLabels lists the states --state accepts, in enum order.
func stateLabels() []string {
	numbers := make([]int, 0, len(platformv1.ProvisioningState_name))
	for n := range platformv1.ProvisioningState_name {
		if n != int32(platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED) {
			numbers = append(numbers, int(n))
		}
	}
	sort.Ints(numbers)
	labels := make([]string, len(numbers))
	for i, n := range numbers {
		labels[i] = stateLabel(platformv1.ProvisioningState(n))
	}
	return labels
}

// parseState maps a CLI state label (or the full enum name) to its value.
func parseState(value string) (platformv1.ProvisioningState, error) {
	name := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	if !strings.HasPrefix(name, statePrefix) {
		name = statePrefix + name
	}
	n, ok := platformv1.ProvisioningState_value[name]
	if !ok || n == int32(platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED) {
		return 0, &ErrInvalidState{Value: value, Valid: stateLabels()}
	}
	return platformv1.ProvisioningState(n), nil
}

func vlanLabel(vlan uint32) string {
	if vlan == 0 {
		return "-"
	}
	return strconv.FormatUint(uint64(vlan), 10)
}

func timeLabel(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "-"
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func detailsLabel(details map[string]string) string {
	pairs := make([]string, 0, len(details))
	for k, v := range details {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ", ")
}
