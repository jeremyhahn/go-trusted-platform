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

//go:build integration

package pxe

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeBinary writes a platformctl stand-in that records its arguments and
// prints reply the way the real CLI does (cli.Printer, JSON).
func fakeBinary(t *testing.T, reply any) (*CLIAdapter, string) {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	require.NoError(t, cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out).Print(reply))
	replyPath := filepath.Join(dir, "reply.json")
	argsPath := filepath.Join(dir, "args")
	require.NoError(t, os.WriteFile(replyPath, out.Bytes(), 0o600))
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsPath + "\ncat " + replyPath + "\n"
	bin := filepath.Join(dir, "platformctl")
	require.NoError(t, os.WriteFile(bin, []byte(script), 0o700))
	return &CLIAdapter{binaryPath: bin, commandTimeout: 10 * time.Second}, argsPath
}

func recordedArgs(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

// The adapter decodes what platformctl prints: enum states, VLANs and
// timestamps survive the CLI's encoding/json rendering of the gRPC reply.
func TestCLIAdapter_GetDecodesCLIReply(t *testing.T) {
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	cliAdapter, argsPath := fakeBinary(t, &platformv1.GetPXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{
		Id:          "dev-1",
		MacAddress:  "00:11:22:33:44:55",
		PortId:      "port-1",
		State:       platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE,
		CurrentVlan: 100,
		TargetVlan:  200,
		RetryCount:  2,
		UpdatedAt:   timestamppb.New(at),
	}})

	got, err := cliAdapter.GetDevice(context.Background(), "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.Equal(t, "00:11:22:33:44:55", got.MACAddress)
	assert.Equal(t, StateInstallComplete, got.State)
	assert.Equal(t, uint16(100), got.CurrentVLAN)
	assert.Equal(t, uint16(200), got.TargetVLAN)
	assert.Equal(t, 2, got.RetryCount)
	assert.True(t, at.Equal(got.UpdatedAt), "updated at = %v", got.UpdatedAt)
	assert.Equal(t, "--output\njson\npxe\nget\ndev-1\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_ListPassesOnlySetFilters(t *testing.T) {
	cliAdapter, argsPath := fakeBinary(t, &platformv1.ListPXEDevicesResponse{
		Devices: []*platformv1.PXEDeviceInfo{{
			Id:    "dev-1",
			State: platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
		}},
		TotalCount: 1,
	})

	got, err := cliAdapter.ListDevices(context.Background(), ListDevicesOptions{State: StateBooting, VLAN: 20})
	require.NoError(t, err)
	require.Len(t, got.Devices, 1)
	assert.Equal(t, StateBooting, got.Devices[0].State)
	assert.Equal(t, int32(1), got.TotalCount)
	assert.Equal(t, "--output\njson\npxe\nlist\n--state\nbooting\n--vlan\n20\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_AuthorizePassesTargetVLAN(t *testing.T) {
	cliAdapter, argsPath := fakeBinary(t, &platformv1.AuthorizePXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{
		Id:         "dev-1",
		State:      platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED,
		TargetVlan: 100,
	}})

	got, err := cliAdapter.AuthorizeDevice(context.Background(), "dev-1", 100)
	require.NoError(t, err)
	assert.Equal(t, StateAuthorized, got.State)
	assert.Equal(t, uint16(100), got.TargetVLAN)
	assert.Equal(t, "--output\njson\npxe\nauthorize\ndev-1\n--target-vlan\n100\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_EventsDecodeTypesAndStates(t *testing.T) {
	cliAdapter, _ := fakeBinary(t, &platformv1.GetPXEEventsResponse{Events: []*platformv1.ProvisioningEvent{{
		Id:        "ev-1",
		DeviceId:  "dev-1",
		FromState: platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
		ToState:   platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
	}}})

	got, err := cliAdapter.GetEvents(context.Background(), "dev-1")
	require.NoError(t, err)
	require.Len(t, got.Events, 1)
	assert.Equal(t, StateDiscovered, got.Events[0].FromState)
	assert.Equal(t, StateBooting, got.Events[0].ToState)
}

func TestCLIAdapter_UndecodableReplyIsTyped(t *testing.T) {
	cliAdapter, _ := fakeBinary(t, "not a device")
	_, err := cliAdapter.RetryDevice(context.Background(), "dev-1")
	var decodeErr ErrCLIDecode
	require.ErrorAs(t, err, &decodeErr)
}

func TestCLIAdapter_RegisterPassesMACAndPort(t *testing.T) {
	cliAdapter, argsPath := fakeBinary(t, &platformv1.RegisterPXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{
		Id:          "dev-1",
		MacAddress:  "02:00:00:00:00:01",
		PortId:      "port-1",
		State:       platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
		CurrentVlan: 999,
	}})

	got, err := cliAdapter.RegisterDevice(context.Background(), RegisterDeviceOptions{
		MACAddress: "02:00:00:00:00:01", PortID: "port-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.Equal(t, "02:00:00:00:00:01", got.MACAddress)
	assert.Equal(t, "port-1", got.PortID)
	assert.Equal(t, StateDiscovered, got.State)
	assert.Equal(t, uint16(999), got.CurrentVLAN)
	assert.Equal(t, "--output\njson\npxe\nregister\n--mac\n02:00:00:00:00:01\n--port\nport-1\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_GetByMACDecodes(t *testing.T) {
	cliAdapter, argsPath := fakeBinary(t, &platformv1.GetPXEDeviceByMACResponse{Device: &platformv1.PXEDeviceInfo{
		Id:         "dev-1",
		MacAddress: "02:00:00:00:00:01",
		State:      platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
	}})

	got, err := cliAdapter.GetDeviceByMAC(context.Background(), "02:00:00:00:00:01")
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.Equal(t, StateBooting, got.State)
	assert.Equal(t, "--output\njson\npxe\nget-by-mac\n02:00:00:00:00:01\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_RemoveReportsRemoved(t *testing.T) {
	cliAdapter, argsPath := fakeBinary(t, &platformv1.RemovePXEDeviceResponse{Status: &platformv1.Status{Success: true}})

	got, err := cliAdapter.RemoveDevice(context.Background(), "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.True(t, got.Removed)
	assert.Equal(t, "--output\njson\npxe\nremove\ndev-1\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_UpdateStatePassesStateAndReason(t *testing.T) {
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	cliAdapter, argsPath := fakeBinary(t, &platformv1.UpdatePXEStateResponse{Device: &platformv1.PXEDeviceInfo{
		Id:          "dev-1",
		State:       platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
		StateReason: "re-image",
		UpdatedAt:   timestamppb.New(at),
	}})

	got, err := cliAdapter.UpdateDeviceState(context.Background(), UpdateStateOptions{
		DeviceID: "dev-1", State: StateBooting, Reason: "re-image",
	})
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.Equal(t, StateBooting, got.ToState)
	assert.Equal(t, "re-image", got.Reason)
	assert.Empty(t, got.FromState, "the reply carries no previous state")
	assert.True(t, at.Equal(got.UpdatedAt), "updated at = %v", got.UpdatedAt)
	assert.Equal(t, "--output\njson\npxe\nset-state\ndev-1\n--state\nbooting\n--reason\nre-image\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_SetEnrolledPassesSerial(t *testing.T) {
	cliAdapter, argsPath := fakeBinary(t, &platformv1.SetPXEDeviceEnrolledResponse{Device: &platformv1.PXEDeviceInfo{
		Id:                "dev-1",
		State:             platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLED,
		CertificateSerial: "0a1b",
	}})

	got, err := cliAdapter.SetDeviceEnrolled(context.Background(), "dev-1", "0a1b")
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.ID)
	assert.Equal(t, StateEnrolled, got.State)
	assert.Equal(t, "0a1b", got.CertificateSerial)
	assert.Equal(t, "--output\njson\npxe\nset-enrolled\ndev-1\n--certificate-serial\n0a1b\n", recordedArgs(t, argsPath))
}

func TestCLIAdapter_StatusDecodes(t *testing.T) {
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	cliAdapter, argsPath := fakeBinary(t, &platformv1.GetPXEStatusResponse{Status: &platformv1.PXEServiceStatus{
		Running:          true,
		DeviceCount:      3,
		StartTime:        timestamppb.New(at),
		IpxeServerAddr:   "192.0.2.10:8080",
		QuarantineVlan:   999,
		ProvisioningVlan: 100,
	}})

	got, err := cliAdapter.GetStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, got.Running)
	assert.Equal(t, 3, got.DeviceCount)
	assert.True(t, at.Equal(got.StartTime), "start time = %v", got.StartTime)
	assert.Equal(t, "192.0.2.10:8080", got.IPXEServerAddr)
	assert.Equal(t, uint16(999), got.QuarantineVLAN)
	assert.Equal(t, uint16(100), got.ProvisioningVLAN)
	assert.Equal(t, "--output\njson\npxe\nstatus\n", recordedArgs(t, argsPath))
}
