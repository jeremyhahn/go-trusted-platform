// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// deviceLifecycleClient is the part of the SDK device client the disable and
// enable commands call.
type deviceLifecycleClient interface {
	Disable(ctx context.Context, id uint64, reason string) (*platformv1.DeviceLifecycleResponse, error)
	Enable(ctx context.Context, id uint64) (*platformv1.DeviceLifecycleResponse, error)
}

// lifecycleOutput is the JSON/YAML shape of a disable or enable result.
type lifecycleOutput struct {
	ID                     uint64 `json:"id"`
	State                  string `json:"state"`
	PreviousState          string `json:"previous_state"`
	StateReason            string `json:"state_reason,omitempty"`
	ReattestationRequested bool   `json:"reattestation_requested"`
}

func newDisableCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "Cut a device off the fabric",
		Long: `Disable a device: the control plane blocks the device's switch port and
records the device suspended. The device keeps its record, its certificates
and its enrollment; only its network access is cut.

The control plane refuses the disable when no SDN policy engine runs on it,
when the device has no switch port on record, or when the device's current
state cannot move to suspended (for example, a revoked device).

Examples:
  # Disable device 123
  platformctl device disable 123

  # Disable with a reason recorded on the device
  platformctl device disable 123 --reason "RMA pending"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceLifecycle(getFlags(), args[0], false, reason)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "",
		"Why the device is disabled; recorded on the device as \"operator: <reason>\"")
	return cmd
}

func newEnableCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <id>",
		Short: "Re-admit a disabled device, pending re-attestation",
		Long: `Enable a disabled device: the control plane unblocks the device's switch
port into the quarantine zone and records the device quarantined. A passing
re-attestation then restores the state and network placement the device held
before it was disabled; a failing one keeps it in quarantine.

Only a suspended device can be enabled.

Examples:
  # Enable device 123
  platformctl device enable 123

  # Machine-readable output
  platformctl device enable 123 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceLifecycle(getFlags(), args[0], true, "")
		},
	}
}

// runDeviceLifecycle disables or enables the device named by idStr.
func runDeviceLifecycle(flags *cli.CommonFlags, idStr string, enable bool, reason string) error {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		return ErrInvalidDeviceID{ID: idStr}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := device.NewClientFromGRPC(base.Client().Device())
	out, err := applyDeviceLifecycle(base.Context(), client, id, enable, reason)
	if err != nil {
		return err
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printDeviceLifecycle(base.Printer(), out, enable)
		return nil
	}
	return base.Output(out)
}

// applyDeviceLifecycle calls the transition and converts the reply.
func applyDeviceLifecycle(ctx context.Context, client deviceLifecycleClient, id uint64, enable bool, reason string) (lifecycleOutput, error) {
	var (
		resp *platformv1.DeviceLifecycleResponse
		err  error
	)
	if enable {
		resp, err = client.Enable(ctx, id)
		if err != nil {
			return lifecycleOutput{}, ErrEnableDeviceFailed{ID: id, Reason: err.Error()}
		}
	} else {
		resp, err = client.Disable(ctx, id, reason)
		if err != nil {
			return lifecycleOutput{}, ErrDisableDeviceFailed{ID: id, Reason: err.Error()}
		}
	}
	return lifecycleOutput{
		ID:                     id,
		State:                  resp.GetState(),
		PreviousState:          resp.GetPreviousState(),
		StateReason:            resp.GetStateReason(),
		ReattestationRequested: resp.GetReattestationRequested(),
	}, nil
}

func printDeviceLifecycle(printer *cli.Printer, out lifecycleOutput, enabled bool) {
	if enabled {
		printer.PrintSuccess("Device enabled; it stays quarantined until it re-attests")
	} else {
		printer.PrintSuccess("Device disabled")
	}
	printer.PrintKeyValue("ID", strconv.FormatUint(out.ID, 10))
	printer.PrintKeyValue("State", out.State)
	printer.PrintKeyValue("Previous State", out.PreviousState)
	if out.StateReason != "" {
		printer.PrintKeyValue("Reason", out.StateReason)
	}
	if enabled {
		printer.PrintKeyValue("Re-attestation Requested", strconv.FormatBool(out.ReattestationRequested))
	}
}
