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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Power Action Tests (with httptest)
// =============================================================================

func TestDoPost_PowerOn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/power", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req powerRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, PowerActionOn, req.Action)

		w.Header().Set("Content-Type", "application/json")
		resp := powerActionResponse{
			ProfileID: "server-01",
			Action:    "on",
			Status:    "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")
	payload := powerRequest{Action: PowerActionOn}

	var resp powerActionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "server-01", resp.ProfileID)
	assert.Equal(t, "on", resp.Action)
	assert.Equal(t, "success", resp.Status)
}

func TestDoPost_PowerOff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req powerRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, PowerActionOff, req.Action)

		w.Header().Set("Content-Type", "application/json")
		resp := powerActionResponse{
			ProfileID: "server-01",
			Action:    "off",
			Status:    "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")
	payload := powerRequest{Action: PowerActionOff}

	var resp powerActionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "off", resp.Action)
}

func TestDoPost_PowerReset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req powerRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, PowerActionReset, req.Action)

		w.Header().Set("Content-Type", "application/json")
		resp := powerActionResponse{
			ProfileID: "server-01",
			Action:    "reset",
			Status:    "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")
	payload := powerRequest{Action: PowerActionReset}

	var resp powerActionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "reset", resp.Action)
}

func TestDoPost_PowerCycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req powerRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, PowerActionCycle, req.Action)

		w.Header().Set("Content-Type", "application/json")
		resp := powerActionResponse{
			ProfileID: "server-01",
			Action:    "cycle",
			Status:    "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")
	payload := powerRequest{Action: PowerActionCycle}

	var resp powerActionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "cycle", resp.Action)
}

// =============================================================================
// Power Status Tests (with httptest)
// =============================================================================

func TestDoGet_PowerStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/power", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := powerStatusResponse{
			ProfileID:  "server-01",
			PowerState: "on",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")

	var resp powerStatusResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.Equal(t, "server-01", resp.ProfileID)
	assert.Equal(t, "on", resp.PowerState)
}

func TestDoGet_PowerStatus_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")

	var resp powerStatusResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusInternalServerError, statusErr.StatusCode)
}

func TestDoGet_PowerStatus_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-valid-json"))
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "power")

	var resp powerStatusResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.Error(t, err)

	var decodeErr ErrResponseDecodeFailed
	require.ErrorAs(t, err, &decodeErr)
}

func TestDoGet_PowerStatus_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	url := buildURL("http://127.0.0.1:1", "server-01", "power")

	var resp powerStatusResponse
	err := doGet(ctx, &http.Client{}, url, &resp)
	require.Error(t, err)

	var reqErr ErrRequestFailed
	require.ErrorAs(t, err, &reqErr)
}

// =============================================================================
// Power Action Validation Tests
// =============================================================================

func TestDoPost_Power_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid profile"))
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "bad-profile", "power")
	payload := powerRequest{Action: PowerActionOn}

	var resp powerActionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusBadRequest, statusErr.StatusCode)
}

func TestDoPost_Power_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	url := buildURL("http://127.0.0.1:1", "server-01", "power")
	payload := powerRequest{Action: PowerActionOn}

	var resp powerActionResponse
	err := doPost(ctx, &http.Client{}, url, payload, &resp)
	require.Error(t, err)

	var reqErr ErrRequestFailed
	require.ErrorAs(t, err, &reqErr)
}

// =============================================================================
// RunPowerAction Validation Tests
// =============================================================================

func TestRunPowerAction_MissingServerURL(t *testing.T) {
	flags := &bmcFlags{profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runPowerAction(flags, PowerActionOn, getFlags)
	require.Error(t, err)

	var urlErr ErrServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestRunPowerAction_MissingProfileID(t *testing.T) {
	flags := &bmcFlags{serverURL: "https://platform:8443"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runPowerAction(flags, PowerActionOn, getFlags)
	require.Error(t, err)

	var pidErr ErrProfileIDRequired
	require.ErrorAs(t, err, &pidErr)
}

func TestRunPowerStatus_MissingServerURL(t *testing.T) {
	flags := &bmcFlags{profileID: "server-01"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runPowerStatus(flags, getFlags)
	require.Error(t, err)

	var urlErr ErrServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestRunPowerStatus_MissingProfileID(t *testing.T) {
	flags := &bmcFlags{serverURL: "https://platform:8443"}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runPowerStatus(flags, getFlags)
	require.Error(t, err)

	var pidErr ErrProfileIDRequired
	require.ErrorAs(t, err, &pidErr)
}

// =============================================================================
// Boot Device Tests (with httptest)
// =============================================================================

func TestDoPost_SetBootDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/boot", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var req bootDeviceRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "pxe", req.Device)
		assert.True(t, req.Persistent)

		w.Header().Set("Content-Type", "application/json")
		resp := bootDeviceResponse{
			ProfileID:  "server-01",
			Device:     "pxe",
			Persistent: true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "boot")
	payload := bootDeviceRequest{Device: "pxe", Persistent: true}

	var resp bootDeviceResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "server-01", resp.ProfileID)
	assert.Equal(t, "pxe", resp.Device)
	assert.True(t, resp.Persistent)
}

func TestDoGet_GetBootDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/boot", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := bootDeviceResponse{
			ProfileID:  "server-01",
			Device:     "disk",
			Persistent: false,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "boot")

	var resp bootDeviceResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.Equal(t, "disk", resp.Device)
	assert.False(t, resp.Persistent)
}

// =============================================================================
// Boot Device Validation Tests
// =============================================================================

func TestRunSetBootDevice_MissingDevice(t *testing.T) {
	flags := &bmcFlags{
		serverURL: "https://platform:8443",
		profileID: "server-01",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSetBootDevice(flags, "", false, getFlags)
	require.Error(t, err)

	var devErr ErrDeviceRequired
	require.ErrorAs(t, err, &devErr)
}

func TestRunSetBootDevice_InvalidDevice(t *testing.T) {
	flags := &bmcFlags{
		serverURL: "https://platform:8443",
		profileID: "server-01",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runSetBootDevice(flags, "floppy", false, getFlags)
	require.Error(t, err)

	var devErr ErrInvalidBootDevice
	require.ErrorAs(t, err, &devErr)
	assert.Equal(t, "floppy", devErr.Device)
}

// =============================================================================
// Virtual Media Tests (with httptest)
// =============================================================================

func TestDoPost_MountISO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/media", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var req mountMediaRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "https://images.example.com/os.iso", req.ISOURL)

		w.Header().Set("Content-Type", "application/json")
		resp := mediaActionResponse{
			ProfileID: "server-01",
			Action:    "mount",
			Status:    "success",
			ISOURL:    "https://images.example.com/os.iso",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "media")
	payload := mountMediaRequest{ISOURL: "https://images.example.com/os.iso"}

	var resp mediaActionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "mount", resp.Action)
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, "https://images.example.com/os.iso", resp.ISOURL)
}

func TestDoDelete_UnmountISO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/media", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := mediaActionResponse{
			ProfileID: "server-01",
			Action:    "unmount",
			Status:    "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "media")

	var resp mediaActionResponse
	err := doDelete(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.Equal(t, "unmount", resp.Action)
	assert.Equal(t, "success", resp.Status)
}

func TestDoGet_MediaStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/media", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := mediaStatusResponse{
			ProfileID: "server-01",
			Mounted:   true,
			ISOURL:    "https://images.example.com/os.iso",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "media")

	var resp mediaStatusResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.True(t, resp.Mounted)
	assert.Equal(t, "https://images.example.com/os.iso", resp.ISOURL)
}

// =============================================================================
// Media Validation Tests
// =============================================================================

func TestRunMountISO_MissingISOURL(t *testing.T) {
	flags := &bmcFlags{
		serverURL: "https://platform:8443",
		profileID: "server-01",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	err := runMountISO(flags, "", getFlags)
	require.Error(t, err)

	var isoErr ErrISOURLRequired
	require.ErrorAs(t, err, &isoErr)
}

// =============================================================================
// Sensors Tests (with httptest)
// =============================================================================

func TestDoGet_Sensors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/sensors", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := sensorsResponse{
			ProfileID: "server-01",
			Sensors: []sensorReading{
				{Name: "CPU Temp", Value: 45.5, Units: "C", Status: "ok"},
				{Name: "Fan 1", Value: 3200, Units: "RPM", Status: "ok"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "sensors")

	var resp sensorsResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.Equal(t, "server-01", resp.ProfileID)
	assert.Len(t, resp.Sensors, 2)
	assert.Equal(t, "CPU Temp", resp.Sensors[0].Name)
	assert.Equal(t, 45.5, resp.Sensors[0].Value)
}

func TestDoGet_Sensors_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := sensorsResponse{
			ProfileID: "server-01",
			Sensors:   []sensorReading{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "sensors")

	var resp sensorsResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.Sensors)
}

// =============================================================================
// System Info Tests (with httptest)
// =============================================================================

func TestDoGet_SystemInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/system", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := systemInfoResponse{
			ProfileID:    "server-01",
			Manufacturer: "Dell Inc.",
			Model:        "PowerEdge R750",
			SerialNumber: "SN12345",
			BIOSVersion:  "2.15.1",
			BMCVersion:   "6.10.30.10",
			PowerState:   "on",
			Health:       "ok",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "system")

	var resp systemInfoResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.NoError(t, err)
	assert.Equal(t, "server-01", resp.ProfileID)
	assert.Equal(t, "Dell Inc.", resp.Manufacturer)
	assert.Equal(t, "PowerEdge R750", resp.Model)
	assert.Equal(t, "SN12345", resp.SerialNumber)
	assert.Equal(t, "on", resp.PowerState)
	assert.Equal(t, "ok", resp.Health)
}

func TestDoGet_SystemInfo_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("profile not found"))
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "unknown-server", "system")

	var resp systemInfoResponse
	err := doGet(ctx, server.Client(), url, &resp)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusNotFound, statusErr.StatusCode)
}

// =============================================================================
// Provision Tests (with httptest)
// =============================================================================

func TestDoPost_Provision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/bmc/server-01/provision", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var req provisionRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "https://images.example.com/os.iso", req.ISOURL)

		w.Header().Set("Content-Type", "application/json")
		resp := provisionResponse{
			ProfileID: "server-01",
			Status:    "provisioning",
			Message:   "ISO mounted, boot device set, server powering on",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "provision")
	payload := provisionRequest{ISOURL: "https://images.example.com/os.iso"}

	var resp provisionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "server-01", resp.ProfileID)
	assert.Equal(t, "provisioning", resp.Status)
	assert.Contains(t, resp.Message, "ISO mounted")
}

func TestDoPost_Provision_NoISO(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req provisionRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Empty(t, req.ISOURL)

		w.Header().Set("Content-Type", "application/json")
		resp := provisionResponse{
			ProfileID: "server-01",
			Status:    "provisioning",
			Message:   "using pre-configured boot settings",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "provision")
	payload := provisionRequest{}

	var resp provisionResponse
	err := doPost(ctx, server.Client(), url, payload, &resp)
	require.NoError(t, err)
	assert.Equal(t, "provisioning", resp.Status)
}

// =============================================================================
// DoDelete Tests
// =============================================================================

func TestDoDelete_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "media")

	var resp mediaActionResponse
	err := doDelete(ctx, server.Client(), url, &resp)
	require.Error(t, err)

	var statusErr ErrUnexpectedStatus
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusInternalServerError, statusErr.StatusCode)
}

func TestDoDelete_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	url := buildURL("http://127.0.0.1:1", "server-01", "media")

	var resp mediaActionResponse
	err := doDelete(ctx, &http.Client{}, url, &resp)
	require.Error(t, err)

	var reqErr ErrRequestFailed
	require.ErrorAs(t, err, &reqErr)
}

func TestDoDelete_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json"))
	}))
	defer server.Close()

	ctx := context.Background()
	url := buildURL(server.URL, "server-01", "media")

	var resp mediaActionResponse
	err := doDelete(ctx, server.Client(), url, &resp)
	require.Error(t, err)

	var decodeErr ErrResponseDecodeFailed
	require.ErrorAs(t, err, &decodeErr)
}
