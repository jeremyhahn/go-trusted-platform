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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// runPowerAction Integration Tests
// =============================================================================

func TestRunPowerAction_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(powerActionResponse{
			ProfileID: "server-01",
			Action:    "on",
			Status:    "success",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runPowerAction(flags, PowerActionOn, getFlags)
	require.NoError(t, err)
}

func TestRunPowerAction_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(powerActionResponse{
			ProfileID: "server-01",
			Action:    "off",
			Status:    "success",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runPowerAction(flags, PowerActionOff, getFlags)
	require.NoError(t, err)
}

func TestRunPowerAction_NilCommonFlags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(powerActionResponse{
			ProfileID: "server-01",
			Action:    "reset",
			Status:    "success",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags { return nil }

	err := runPowerAction(flags, PowerActionReset, getFlags)
	require.NoError(t, err)
}

// =============================================================================
// runPowerStatus Integration Tests
// =============================================================================

func TestRunPowerStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(powerStatusResponse{
			ProfileID:  "server-01",
			PowerState: "on",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runPowerStatus(flags, getFlags)
	require.NoError(t, err)
}

func TestRunPowerStatus_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(powerStatusResponse{
			ProfileID:  "server-01",
			PowerState: "off",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runPowerStatus(flags, getFlags)
	require.NoError(t, err)
}

// =============================================================================
// runSetBootDevice Integration Tests
// =============================================================================

func TestRunSetBootDevice_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bootDeviceResponse{
			ProfileID:  "server-01",
			Device:     "pxe",
			Persistent: true,
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSetBootDevice(flags, "pxe", true, getFlags)
	require.NoError(t, err)
}

func TestRunSetBootDevice_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bootDeviceResponse{
			ProfileID:  "server-01",
			Device:     "disk",
			Persistent: false,
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runSetBootDevice(flags, "disk", false, getFlags)
	require.NoError(t, err)
}

func TestRunSetBootDevice_MissingFlags(t *testing.T) {
	flags := &bmcFlags{}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSetBootDevice(flags, "pxe", false, getFlags)
	require.Error(t, err)

	var urlErr ErrServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestRunSetBootDevice_AllValidDevices(t *testing.T) {
	for _, device := range []string{"pxe", "disk", "cdrom", "bios"} {
		t.Run(device, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(bootDeviceResponse{
					ProfileID: "server-01",
					Device:    device,
				})
			}))
			defer server.Close()

			flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
			}

			err := runSetBootDevice(flags, device, false, getFlags)
			require.NoError(t, err)
		})
	}
}

// =============================================================================
// runGetBootDevice Integration Tests
// =============================================================================

func TestRunGetBootDevice_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bootDeviceResponse{
			ProfileID:  "server-01",
			Device:     "disk",
			Persistent: true,
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runGetBootDevice(flags, getFlags)
	require.NoError(t, err)
}

func TestRunGetBootDevice_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bootDeviceResponse{
			ProfileID: "server-01",
			Device:    "cdrom",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runGetBootDevice(flags, getFlags)
	require.NoError(t, err)
}

func TestRunGetBootDevice_MissingFlags(t *testing.T) {
	flags := &bmcFlags{serverURL: "https://example.com"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runGetBootDevice(flags, getFlags)
	require.Error(t, err)

	var pidErr ErrProfileIDRequired
	require.ErrorAs(t, err, &pidErr)
}

// =============================================================================
// runMountISO Integration Tests
// =============================================================================

func TestRunMountISO_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaActionResponse{
			ProfileID: "server-01",
			Action:    "mount",
			Status:    "success",
			ISOURL:    "https://images.example.com/os.iso",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runMountISO(flags, "https://images.example.com/os.iso", getFlags)
	require.NoError(t, err)
}

func TestRunMountISO_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaActionResponse{
			ProfileID: "server-01",
			Action:    "mount",
			Status:    "success",
			ISOURL:    "https://images.example.com/os.iso",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runMountISO(flags, "https://images.example.com/os.iso", getFlags)
	require.NoError(t, err)
}

// =============================================================================
// runUnmountISO Integration Tests
// =============================================================================

func TestRunUnmountISO_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaActionResponse{
			ProfileID: "server-01",
			Action:    "unmount",
			Status:    "success",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runUnmountISO(flags, getFlags)
	require.NoError(t, err)
}

func TestRunUnmountISO_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaActionResponse{
			ProfileID: "server-01",
			Action:    "unmount",
			Status:    "success",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runUnmountISO(flags, getFlags)
	require.NoError(t, err)
}

func TestRunUnmountISO_MissingFlags(t *testing.T) {
	flags := &bmcFlags{}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runUnmountISO(flags, getFlags)
	require.Error(t, err)

	var urlErr ErrServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

// =============================================================================
// runMediaStatus Integration Tests
// =============================================================================

func TestRunMediaStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaStatusResponse{
			ProfileID: "server-01",
			Mounted:   true,
			ISOURL:    "https://images.example.com/os.iso",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runMediaStatus(flags, getFlags)
	require.NoError(t, err)
}

func TestRunMediaStatus_TableOutput_WithISO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaStatusResponse{
			ProfileID: "server-01",
			Mounted:   true,
			ISOURL:    "https://images.example.com/os.iso",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runMediaStatus(flags, getFlags)
	require.NoError(t, err)
}

func TestRunMediaStatus_TableOutput_NoISO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mediaStatusResponse{
			ProfileID: "server-01",
			Mounted:   false,
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runMediaStatus(flags, getFlags)
	require.NoError(t, err)
}

func TestRunMediaStatus_MissingFlags(t *testing.T) {
	flags := &bmcFlags{serverURL: "https://example.com"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runMediaStatus(flags, getFlags)
	require.Error(t, err)

	var pidErr ErrProfileIDRequired
	require.ErrorAs(t, err, &pidErr)
}

// =============================================================================
// runSensors Integration Tests
// =============================================================================

func TestRunSensors_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]sensorReading{
			{Name: "CPU Temp", Value: 42.0, Units: "C", Status: "ok"},
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSensors(flags, getFlags)
	require.NoError(t, err)
}

func TestRunSensors_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]sensorReading{
			{Name: "CPU Temp", Value: 45.5, Units: "C", Status: "ok"},
			{Name: "Fan 1", Value: 3200, Units: "RPM", Status: "ok"},
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runSensors(flags, getFlags)
	require.NoError(t, err)
}

func TestRunSensors_MissingFlags(t *testing.T) {
	flags := &bmcFlags{}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSensors(flags, getFlags)
	require.Error(t, err)
}

// =============================================================================
// runSystemInfo Integration Tests
// =============================================================================

func TestRunSystemInfo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(systemInfoResponse{
			ProfileID:    "server-01",
			Manufacturer: "Dell Inc.",
			Model:        "PowerEdge R750",
			SerialNumber: "SN12345",
			BIOSVersion:  "2.15.1",
			BMCVersion:   "6.10.30.10",
			PowerState:   "on",
			Health:       "ok",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSystemInfo(flags, getFlags)
	require.NoError(t, err)
}

func TestRunSystemInfo_TableOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(systemInfoResponse{
			ProfileID:    "server-01",
			Manufacturer: "HP",
			Model:        "DL380",
			SerialNumber: "HP99999",
			BIOSVersion:  "1.0",
			BMCVersion:   "2.0",
			PowerState:   "off",
			Health:       "warning",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runSystemInfo(flags, getFlags)
	require.NoError(t, err)
}

func TestRunSystemInfo_MissingFlags(t *testing.T) {
	flags := &bmcFlags{}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSystemInfo(flags, getFlags)
	require.Error(t, err)
}

// =============================================================================
// runProvision Integration Tests
// =============================================================================

func TestRunProvision_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(provisionResponse{
			ProfileID: "server-01",
			Status:    "provisioning",
			Message:   "ISO mounted, boot device set",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runProvision(flags, "https://images.example.com/os.iso", getFlags)
	require.NoError(t, err)
}

func TestRunProvision_TableOutput_WithMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(provisionResponse{
			ProfileID: "server-01",
			Status:    "provisioning",
			Message:   "using pre-configured settings",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runProvision(flags, "", getFlags)
	require.NoError(t, err)
}

func TestRunProvision_TableOutput_NoMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(provisionResponse{
			ProfileID: "server-01",
			Status:    "provisioning",
		})
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormat("table")}
	}

	err := runProvision(flags, "", getFlags)
	require.NoError(t, err)
}

func TestRunProvision_MissingFlags(t *testing.T) {
	flags := &bmcFlags{}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runProvision(flags, "https://example.com/os.iso", getFlags)
	require.Error(t, err)
}

func TestRunProvision_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	flags := &bmcFlags{serverURL: server.URL, profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runProvision(flags, "", getFlags)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
}
