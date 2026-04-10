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

package bmc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// emitJSON writes the value as JSON when the user requested JSON output and
// reports whether the caller should suppress the human-readable rendering.
func emitJSON(getFlags func() *cli.CommonFlags, v any) (bool, error) {
	common := getFlags()
	if common == nil || common.OutputFormat != cli.OutputFormatJSON {
		return false, nil
	}
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		return true, ErrResponseDecodeFailed{Cause: err}
	}
	return true, nil
}

// withStandaloneClient is the common entry point for standalone-mode dispatch.
// It validates flag conflicts, builds a bmc.Client, runs fn against it, and
// guarantees Close() runs regardless of fn's outcome.
func withStandaloneClient(
	ctx context.Context,
	standalone *standaloneBMCFlags,
	fn func(ctx context.Context, client bmc.Client) error,
) error {
	client, err := resolveBMCClient(ctx, standalone, standaloneLogger())
	if err != nil {
		return err
	}
	defer client.Close()
	return fn(ctx, client)
}

// runStandalonePower executes a power action via a direct bmc.Client.
func runStandalonePower(ctx context.Context, standalone *standaloneBMCFlags, action PowerAction, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		var actionErr error
		switch action {
		case PowerActionOn:
			actionErr = client.PowerOn(ctx)
		case PowerActionOff:
			actionErr = client.PowerOff(ctx)
		case PowerActionReset:
			actionErr = client.PowerReset(ctx)
		case PowerActionCycle:
			actionErr = client.PowerCycle(ctx)
		default:
			return ErrInvalidPowerAction{Action: string(action)}
		}
		if actionErr != nil {
			return actionErr
		}
		resp := powerActionResponse{
			ProfileID: standalone.host,
			Action:    string(action),
			Status:    "success",
		}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:   %s\nAction: %s\nStatus: %s\n", resp.ProfileID, resp.Action, resp.Status)
		return nil
	})
}

// runStandalonePowerStatus reports the current power state via a direct bmc.Client.
func runStandalonePowerStatus(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		state, err := client.PowerStatus(ctx)
		if err != nil {
			return err
		}
		resp := powerStatusResponse{ProfileID: standalone.host, PowerState: string(state)}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:        %s\nPower State: %s\n", resp.ProfileID, resp.PowerState)
		return nil
	})
}

// runStandaloneSetBootDevice sets the next boot device via a direct bmc.Client.
func runStandaloneSetBootDevice(ctx context.Context, standalone *standaloneBMCFlags, device string, persistent bool, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		dev := bmc.BootDevice(device)
		if !dev.IsValid() {
			return ErrInvalidBootDevice{Device: device}
		}
		if err := client.SetBootDevice(ctx, dev, persistent); err != nil {
			return err
		}
		resp := bootDeviceResponse{ProfileID: standalone.host, Device: device, Persistent: persistent}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:       %s\nDevice:     %s\nPersistent: %t\n", resp.ProfileID, resp.Device, resp.Persistent)
		return nil
	})
}

// runStandaloneGetBootDevice queries the boot device override via a direct bmc.Client.
func runStandaloneGetBootDevice(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		dev, err := client.GetBootDevice(ctx)
		if err != nil {
			return err
		}
		resp := bootDeviceResponse{ProfileID: standalone.host, Device: string(dev)}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:       %s\nDevice:     %s\nPersistent: %t\n", resp.ProfileID, resp.Device, resp.Persistent)
		return nil
	})
}

// runStandaloneMountISO mounts an ISO via virtual media using a direct bmc.Client.
func runStandaloneMountISO(ctx context.Context, standalone *standaloneBMCFlags, isoURL string, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		if err := client.MountISO(ctx, isoURL); err != nil {
			return err
		}
		resp := mediaActionResponse{ProfileID: standalone.host, Action: "mount", Status: "success", ISOURL: isoURL}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:    %s\nAction:  %s\nStatus:  %s\nISO URL: %s\n", resp.ProfileID, resp.Action, resp.Status, resp.ISOURL)
		return nil
	})
}

// runStandaloneUnmountISO unmounts virtual media via a direct bmc.Client.
func runStandaloneUnmountISO(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		if err := client.UnmountISO(ctx); err != nil {
			return err
		}
		resp := mediaActionResponse{ProfileID: standalone.host, Action: "unmount", Status: "success"}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:   %s\nAction: %s\nStatus: %s\n", resp.ProfileID, resp.Action, resp.Status)
		return nil
	})
}

// runStandaloneMediaStatus reports the current virtual media state via a direct bmc.Client.
func runStandaloneMediaStatus(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		info, err := client.VirtualMediaStatus(ctx)
		if err != nil {
			return err
		}
		resp := mediaStatusResponse{ProfileID: standalone.host, Mounted: info.Mounted, ISOURL: info.ImageURL}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:    %s\nMounted: %t\n", resp.ProfileID, resp.Mounted)
		if resp.ISOURL != "" {
			fmt.Fprintf(os.Stdout, "ISO URL: %s\n", resp.ISOURL)
		}
		return nil
	})
}

// runStandaloneSensors prints sensor readings via a direct bmc.Client.
func runStandaloneSensors(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		readings, err := client.GetSensors(ctx)
		if err != nil {
			return err
		}
		out := sensorsResponse{ProfileID: standalone.host}
		for _, r := range readings {
			out.Sensors = append(out.Sensors, sensorReading{Name: r.Name, Value: r.Value, Units: r.Units, Status: r.Status})
		}
		done, err := emitJSON(getFlags, out)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host: %s\nSensors:\n", out.ProfileID)
		for _, s := range out.Sensors {
			fmt.Fprintf(os.Stdout, "  %-30s %8.2f %-10s [%s]\n", s.Name, s.Value, s.Units, s.Status)
		}
		return nil
	})
}

// runStandaloneSystemInfo prints system information via a direct bmc.Client.
func runStandaloneSystemInfo(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneClient(ctx, standalone, func(ctx context.Context, client bmc.Client) error {
		info, err := client.GetSystemInfo(ctx)
		if err != nil {
			return err
		}
		resp := systemInfoResponse{
			ProfileID:    standalone.host,
			Manufacturer: info.Manufacturer,
			Model:        info.Product,
			SerialNumber: info.SerialNumber,
			BIOSVersion:  info.BIOSVersion,
			BMCVersion:   info.FirmwareVersion,
			PowerState:   string(info.PowerState),
		}
		done, err := emitJSON(getFlags, resp)
		if err != nil || done {
			return err
		}
		fmt.Fprintf(os.Stdout, "Host:          %s\n", resp.ProfileID)
		fmt.Fprintf(os.Stdout, "Manufacturer:  %s\n", resp.Manufacturer)
		fmt.Fprintf(os.Stdout, "Model:         %s\n", resp.Model)
		fmt.Fprintf(os.Stdout, "Serial Number: %s\n", resp.SerialNumber)
		fmt.Fprintf(os.Stdout, "BIOS Version:  %s\n", resp.BIOSVersion)
		fmt.Fprintf(os.Stdout, "BMC Version:   %s\n", resp.BMCVersion)
		fmt.Fprintf(os.Stdout, "Power State:   %s\n", resp.PowerState)
		return nil
	})
}
