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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// mockRedfishServer creates an httptest.Server that simulates a Redfish BMC API.
// It returns the server and a mutable state struct for controlling responses.
func mockRedfishServer(t *testing.T) (*httptest.Server, *mockRedfishState) {
	t.Helper()
	state := &mockRedfishState{
		powerState:   "On",
		bootTarget:   "Hdd",
		bootEnabled:  "Once",
		inserted:     false,
		imageURL:     "",
		manufacturer: "TestVendor",
		model:        "TestServer 1000",
	}

	mux := http.NewServeMux()

	// Service root.
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishServiceRoot{
			Systems:  redfishRef{ODataID: "/redfish/v1/Systems"},
			Chassis:  redfishRef{ODataID: "/redfish/v1/Chassis"},
			Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
		})
	})

	// Systems collection.
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Systems" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishCollection{
			Members: []redfishRef{{ODataID: "/redfish/v1/Systems/1"}},
		})
	})

	// System resource.
	mux.HandleFunc("/redfish/v1/Systems/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			var patch redfishBootPatch
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			state.bootTarget = patch.Boot.BootSourceOverrideTarget
			state.bootEnabled = patch.Boot.BootSourceOverrideEnabled
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, redfishSystem{
			Manufacturer: state.manufacturer,
			Model:        state.model,
			PartNumber:   state.partNumber,
			SerialNumber: "SN123456",
			BiosVersion:  "2.1.0",
			PowerState:   state.powerState,
			Boot: redfishBoot{
				BootSourceOverrideTarget:  state.bootTarget,
				BootSourceOverrideEnabled: state.bootEnabled,
			},
			ProcessorSummary: redfishProcessorSummary{
				Count: 2,
				Model: "Intel Xeon E5-2680",
			},
			MemorySummary: redfishMemorySummary{
				TotalSystemMemoryGiB: 128,
			},
			Actions: redfishActions{
				ComputerSystemReset: redfishResetAction{
					Target: "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
				},
			},
		})
	})

	// Reset action.
	mux.HandleFunc("/redfish/v1/Systems/1/Actions/ComputerSystem.Reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body redfishResetBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch body.ResetType {
		case "On":
			state.powerState = "On"
		case "ForceOff":
			state.powerState = "Off"
		case "ForceRestart":
			state.powerState = "On"
		case "PowerCycle":
			state.powerState = "On"
		default:
			http.Error(w, "unknown reset type", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Chassis collection.
	mux.HandleFunc("/redfish/v1/Chassis", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Chassis" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishCollection{
			Members: []redfishRef{{ODataID: "/redfish/v1/Chassis/1"}},
		})
	})

	// Thermal.
	mux.HandleFunc("/redfish/v1/Chassis/1/Thermal", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishThermal{
			Temperatures: []redfishTemperature{
				{
					Name:           "CPU1 Temp",
					ReadingCelsius: 42.5,
					Status:         redfishStatus{Health: "OK"},
				},
				{
					Name:           "Inlet Temp",
					ReadingCelsius: 22.0,
					Status:         redfishStatus{Health: "OK"},
				},
			},
			Fans: []redfishFan{
				{
					Name:         "Fan1",
					Reading:      8500,
					ReadingUnits: "RPM",
					Status:       redfishStatus{Health: "OK"},
				},
				{
					Name:         "Fan2",
					Reading:      8200,
					ReadingUnits: "RPM",
					Status:       redfishStatus{Health: "Warning"},
				},
			},
		})
	})

	// Power.
	mux.HandleFunc("/redfish/v1/Chassis/1/Power", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishPower{
			PowerControl: []redfishPowerControl{
				{
					Name:               "Server Power",
					PowerConsumedWatts: 350,
					PowerCapacityWatts: 800,
				},
			},
			PowerSupplies: []redfishPowerSupply{
				{
					Name:                 "PSU1",
					PowerCapacityWatts:   800,
					LastPowerOutputWatts: 175,
					Status:               redfishStatus{Health: "OK"},
				},
				{
					Name:                 "PSU2",
					PowerCapacityWatts:   800,
					LastPowerOutputWatts: 175,
					Status:               redfishStatus{Health: "OK"},
				},
			},
		})
	})

	// Managers collection.
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Managers" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishCollection{
			Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}},
		})
	})

	// Manager resource with VirtualMedia link.
	mux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Managers/1" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, struct {
			VirtualMedia redfishRef `json:"VirtualMedia"`
		}{
			VirtualMedia: redfishRef{ODataID: "/redfish/v1/Managers/1/VirtualMedia"},
		})
	})

	// Virtual media collection.
	mux.HandleFunc("/redfish/v1/Managers/1/VirtualMedia", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Managers/1/VirtualMedia" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishCollection{
			Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1/VirtualMedia/CD"}},
		})
	})

	// Virtual media CD member.
	mux.HandleFunc("/redfish/v1/Managers/1/VirtualMedia/CD", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Managers/1/VirtualMedia/CD" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, redfishVirtualMedia{
			Inserted:   state.inserted,
			Image:      state.imageURL,
			MediaTypes: []string{"CD", "DVD"},
			Actions: struct {
				InsertMedia redfishRef `json:"#VirtualMedia.InsertMedia"`
				EjectMedia  redfishRef `json:"#VirtualMedia.EjectMedia"`
			}{
				InsertMedia: redfishRef{ODataID: "/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia"},
				EjectMedia:  redfishRef{ODataID: "/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.EjectMedia"},
			},
		})
	})

	// Insert media action.
	mux.HandleFunc("/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body redfishInsertMediaBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		state.inserted = true
		state.imageURL = body.Image
		w.WriteHeader(http.StatusOK)
	})

	// Eject media action.
	mux.HandleFunc("/redfish/v1/Managers/1/VirtualMedia/CD/Actions/VirtualMedia.EjectMedia", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Read and discard body.
		_, _ = io.ReadAll(r.Body)
		state.inserted = false
		state.imageURL = ""
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewTLSServer(mux)
	return server, state
}

// mockRedfishState holds mutable state for the mock Redfish server.
type mockRedfishState struct {
	powerState  string
	bootTarget  string
	bootEnabled string
	inserted    bool
	imageURL    string
	// Hardware identity served on the system resource; set before the
	// client's first discovery to simulate a specific board.
	manufacturer string
	model        string
	partNumber   string
}

// newTestRedfishClient creates a redfishClient configured to use the given test server.
func newTestRedfishClient(t *testing.T, server *httptest.Server) *redfishClient {
	t.Helper()

	logger := slog.Default()
	rc := &redfishClient{
		logger: logger,
		transport: &redfishTransport{
			httpClient: server.Client(),
			baseURL:    server.URL,
			username:   "admin",
			password:   memguard.NewMemoryEnclaveFromString("password"),
			logger:     logger,
		},
	}
	return rc
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// --- Discovery Tests ---

func TestRedfishClient_Discovery(t *testing.T) {
	server, _ := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("successful discovery", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.discover(context.Background())
		if err != nil {
			t.Fatalf("discovery failed: %v", err)
		}

		if got := client.getSystemPath(); got != "/redfish/v1/Systems/1" {
			t.Errorf("systemPath = %q, want /redfish/v1/Systems/1", got)
		}
		if got := client.getChassisPath(); got != "/redfish/v1/Chassis/1" {
			t.Errorf("chassisPath = %q, want /redfish/v1/Chassis/1", got)
		}
		if got := client.getVirtualMediaPath(); got != "/redfish/v1/Managers/1/VirtualMedia" {
			t.Errorf("virtualMediaPath = %q, want /redfish/v1/Managers/1/VirtualMedia", got)
		}
		if got := client.getResetActionPath(); got != "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" {
			t.Errorf("resetActionPath = %q, want /redfish/v1/Systems/1/Actions/ComputerSystem.Reset", got)
		}
	})

	t.Run("discovery with closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		err := client.ensureDiscovered(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})
}

// TestRedfishClient_Discovery_CachesIdentityAndResolvesQuirk verifies that
// discovery caches all three identity fields from the system resource and
// that the mini-fleet ATEN firmware identity (issue #101: placeholder Model,
// board named only by PartNumber) resolves to the X10SDV quirk set rather
// than the manufacturer-wide Supermicro entry.
func TestRedfishClient_Discovery_CachesIdentityAndResolvesQuirk(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)
	state.manufacturer = "Supermicro"
	state.model = "Super Server"
	state.partNumber = "SYS-5018D-FN8T-AS001"

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	if q := client.resolveQuirk(); q.Key != "default" {
		t.Fatalf("quirk before discovery = %q, want default", q.Key)
	}
	if err := client.discover(context.Background()); err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	if got := client.getManufacturer(); got != "Supermicro" {
		t.Errorf("manufacturer = %q, want Supermicro", got)
	}
	if got := client.getModel(); got != "Super Server" {
		t.Errorf("model = %q, want Super Server", got)
	}
	if got := client.getPartNumber(); got != "SYS-5018D-FN8T-AS001" {
		t.Errorf("partNumber = %q, want SYS-5018D-FN8T-AS001", got)
	}
	q := client.resolveQuirk()
	if q.Key != "supermicro/x10sdv" {
		t.Errorf("quirk = %q, want supermicro/x10sdv", q.Key)
	}
	if q.Model != "X10SDV" {
		t.Errorf("Model = %q, want the X10SDV entry's own model", q.Model)
	}
}

// TestRedfishClient_Discovery_UnknownVendorResolvesDefault verifies the
// generic mock identity (no registry entry) resolves to the default quirk
// after discovery, so an unrecognised board never inherits vendor behaviour.
func TestRedfishClient_Discovery_UnknownVendorResolvesDefault(t *testing.T) {
	server, _ := mockRedfishServer(t)
	t.Cleanup(server.Close)

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	if err := client.discover(context.Background()); err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if got := client.getPartNumber(); got != "" {
		t.Errorf("partNumber = %q, want empty", got)
	}
	if q := client.resolveQuirk(); q.Key != "default" {
		t.Errorf("quirk = %q, want default", q.Key)
	}
}

func TestRedfishClient_Discovery_BadServer(t *testing.T) {
	// Server that returns no members in Systems collection.
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishServiceRoot{
			Systems:  redfishRef{ODataID: "/redfish/v1/Systems"},
			Chassis:  redfishRef{ODataID: "/redfish/v1/Chassis"},
			Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{}})
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	err := client.discover(context.Background())
	if err == nil {
		t.Fatal("expected discovery error for empty Systems collection")
	}
	var target ErrRedfishDiscovery
	if !errors.As(err, &target) {
		t.Errorf("expected ErrRedfishDiscovery, got %T: %v", err, err)
	}
}

// TestRedfishClient_Discovery_ChassisUnavailable verifies that a BMC
// that fails Chassis discovery (e.g., Supermicro X10 ATEN firmware
// intermittently returning 503 on /redfish/v1/Chassis) still completes
// discovery: System / Manager / VirtualMedia are independent and must
// remain usable. GetSensors should degrade gracefully to an empty
// reading set instead of issuing requests against an empty path.
func TestRedfishClient_Discovery_ChassisUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishServiceRoot{
			Systems:  redfishRef{ODataID: "/redfish/v1/Systems"},
			Chassis:  redfishRef{ODataID: "/redfish/v1/Chassis"},
			Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Systems/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Systems/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishSystem{
			Actions: redfishActions{
				ComputerSystemReset: redfishResetAction{
					Target: "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
				},
			},
		})
	})
	mux.HandleFunc("/redfish/v1/Chassis", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "503 Service Not Available", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, struct {
			VirtualMedia redfishRef `json:"VirtualMedia"`
		}{VirtualMedia: redfishRef{ODataID: "/redfish/v1/Managers/1/VirtualMedia"}})
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	if err := client.discover(context.Background()); err != nil {
		t.Fatalf("discovery should succeed even when Chassis returns 503, got: %v", err)
	}
	if got := client.getSystemPath(); got != "/redfish/v1/Systems/1" {
		t.Errorf("systemPath = %q, want /redfish/v1/Systems/1", got)
	}
	if got := client.getChassisPath(); got != "" {
		t.Errorf("chassisPath = %q, want empty (Chassis was unreachable)", got)
	}
	if got := client.getVirtualMediaPath(); got != "/redfish/v1/Managers/1/VirtualMedia" {
		t.Errorf("virtualMediaPath = %q, want /redfish/v1/Managers/1/VirtualMedia", got)
	}

	// GetSensors should return an empty result, not error, when
	// Chassis is unavailable.
	sensors, err := client.GetSensors(context.Background())
	if err != nil {
		t.Errorf("GetSensors() error when Chassis empty: %v", err)
	}
	if len(sensors) != 0 {
		t.Errorf("GetSensors() = %d readings, want 0 (Chassis was unreachable)", len(sensors))
	}
}

// --- Power Tests ---

func TestRedfishClient_PowerStatus(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("power on", func(t *testing.T) {
		state.powerState = "On"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		got, err := client.PowerStatus(context.Background())
		if err != nil {
			t.Fatalf("PowerStatus() error: %v", err)
		}
		if got != PowerStateOn {
			t.Errorf("PowerStatus() = %q, want %q", got, PowerStateOn)
		}
	})

	t.Run("power off", func(t *testing.T) {
		state.powerState = "Off"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		got, err := client.PowerStatus(context.Background())
		if err != nil {
			t.Fatalf("PowerStatus() error: %v", err)
		}
		if got != PowerStateOff {
			t.Errorf("PowerStatus() = %q, want %q", got, PowerStateOff)
		}
	})

	t.Run("unknown power state", func(t *testing.T) {
		state.powerState = "SomethingWeird"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		got, err := client.PowerStatus(context.Background())
		if err != nil {
			t.Fatalf("PowerStatus() error: %v", err)
		}
		if got != PowerStateUnknown {
			t.Errorf("PowerStatus() = %q, want %q", got, PowerStateUnknown)
		}
	})

	t.Run("power status on closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		_, err := client.PowerStatus(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
	})
}

func TestRedfishClient_PowerOn(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("successful power on", func(t *testing.T) {
		state.powerState = "Off"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.PowerOn(context.Background())
		if err != nil {
			t.Fatalf("PowerOn() error: %v", err)
		}
		if state.powerState != "On" {
			t.Errorf("server state = %q, want On", state.powerState)
		}
	})

	t.Run("power on closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		err := client.PowerOn(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
		var target ErrPowerOperation
		if !errors.As(err, &target) {
			t.Errorf("expected ErrPowerOperation, got %T: %v", err, err)
		}
	})
}

func TestRedfishClient_PowerOff(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	state.powerState = "On"
	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	err := client.PowerOff(context.Background())
	if err != nil {
		t.Fatalf("PowerOff() error: %v", err)
	}
	if state.powerState != "Off" {
		t.Errorf("server state = %q, want Off", state.powerState)
	}
}

func TestRedfishClient_PowerReset(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	state.powerState = "On"
	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	err := client.PowerReset(context.Background())
	if err != nil {
		t.Fatalf("PowerReset() error: %v", err)
	}
	if state.powerState != "On" {
		t.Errorf("server state = %q, want On after reset", state.powerState)
	}
}

func TestRedfishClient_PowerCycle(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	state.powerState = "On"
	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	err := client.PowerCycle(context.Background())
	if err != nil {
		t.Fatalf("PowerCycle() error: %v", err)
	}
	if state.powerState != "On" {
		t.Errorf("server state = %q, want On after cycle", state.powerState)
	}
}

// --- Boot Device Tests ---

func TestRedfishClient_GetBootDevice(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("HDD boot device", func(t *testing.T) {
		state.bootTarget = "Hdd"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		got, err := client.GetBootDevice(context.Background())
		if err != nil {
			t.Fatalf("GetBootDevice() error: %v", err)
		}
		if got != BootDeviceDisk {
			t.Errorf("GetBootDevice() = %q, want %q", got, BootDeviceDisk)
		}
	})

	t.Run("PXE boot device", func(t *testing.T) {
		state.bootTarget = "Pxe"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		got, err := client.GetBootDevice(context.Background())
		if err != nil {
			t.Fatalf("GetBootDevice() error: %v", err)
		}
		if got != BootDevicePXE {
			t.Errorf("GetBootDevice() = %q, want %q", got, BootDevicePXE)
		}
	})

	t.Run("unknown boot device returns none", func(t *testing.T) {
		state.bootTarget = "UnknownDevice"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		got, err := client.GetBootDevice(context.Background())
		if err != nil {
			t.Fatalf("GetBootDevice() error: %v", err)
		}
		if got != BootDeviceNone {
			t.Errorf("GetBootDevice() = %q, want %q", got, BootDeviceNone)
		}
	})

	t.Run("get boot device closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		_, err := client.GetBootDevice(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
	})
}

func TestRedfishClient_SetBootDevice(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("set PXE once", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.SetBootDevice(context.Background(), BootDevicePXE, false)
		if err != nil {
			t.Fatalf("SetBootDevice() error: %v", err)
		}
		if state.bootTarget != "Pxe" {
			t.Errorf("server bootTarget = %q, want Pxe", state.bootTarget)
		}
		if state.bootEnabled != "Once" {
			t.Errorf("server bootEnabled = %q, want Once", state.bootEnabled)
		}
	})

	t.Run("set disk persistent", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.SetBootDevice(context.Background(), BootDeviceDisk, true)
		if err != nil {
			t.Fatalf("SetBootDevice() error: %v", err)
		}
		if state.bootTarget != "Hdd" {
			t.Errorf("server bootTarget = %q, want Hdd", state.bootTarget)
		}
		if state.bootEnabled != "Continuous" {
			t.Errorf("server bootEnabled = %q, want Continuous", state.bootEnabled)
		}
	})

	t.Run("set CDROM", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.SetBootDevice(context.Background(), BootDeviceCDROM, false)
		if err != nil {
			t.Fatalf("SetBootDevice() error: %v", err)
		}
		if state.bootTarget != "Cd" {
			t.Errorf("server bootTarget = %q, want Cd", state.bootTarget)
		}
	})

	t.Run("invalid boot device", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.SetBootDevice(context.Background(), BootDevice("invalid"), false)
		if err == nil {
			t.Fatal("expected error for invalid boot device")
		}
		var target ErrInvalidBootDevice
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidBootDevice, got %T: %v", err, err)
		}
	})

	t.Run("set boot device closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		err := client.SetBootDevice(context.Background(), BootDevicePXE, false)
		if err == nil {
			t.Fatal("expected error for closed client")
		}
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Errorf("expected ErrBootDevice, got %T: %v", err, err)
		}
	})
}

// TestRedfishClient_SetBootDevice_NoneDisablesOverride verifies the clear
// PATCHes Target=None with Enabled=Disabled — the combination measured to
// clear both the Redfish and IPMI views on X10 ATEN firmware (issue #103)
// — and that a vendor quirk's Continuous forcing never applies to None.
func TestRedfishClient_SetBootDevice_NoneDisablesOverride(t *testing.T) {
	t.Run("generic vendor", func(t *testing.T) {
		server, state := mockRedfishServer(t)
		t.Cleanup(server.Close)
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		if err := client.SetBootDevice(context.Background(), BootDeviceNone, false); err != nil {
			t.Fatalf("SetBootDevice(None) error: %v", err)
		}
		if state.bootTarget != "None" || state.bootEnabled != bootOverrideDisabled {
			t.Errorf("PATCH = (%q, %q), want (None, Disabled)", state.bootTarget, state.bootEnabled)
		}
	})

	t.Run("Supermicro: OEM disable then Redfish None/Disabled", func(t *testing.T) {
		server, state := mockRedfishServer(t)
		t.Cleanup(server.Close)
		state.manufacturer = "Supermicro"
		state.model = "Super Server"
		state.partNumber = "SYS-5018D-FN8T-AS001"
		state.bootTarget = "UefiUsbCd"
		state.bootEnabled = bootOverrideContinuous

		fake := newFakeIPMISession()
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })
		client.config = &Config{Address: "127.0.0.1", Port: 443, Username: "admin", Password: "secret"}
		client.openIPMISession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			return fake, nil
		}

		if err := client.SetBootDevice(context.Background(), BootDeviceNone, false); err != nil {
			t.Fatalf("SetBootDevice(None) error: %v", err)
		}
		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected the OEM disable to be issued first")
		}
		if want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootDisable}; !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
		if state.bootTarget != "None" || state.bootEnabled != bootOverrideDisabled {
			t.Errorf("PATCH after OEM disable = (%q, %q), want (None, Disabled)", state.bootTarget, state.bootEnabled)
		}
	})

	t.Run("Supermicro: PXE via OEM still skips the PATCH", func(t *testing.T) {
		server, state := mockRedfishServer(t)
		t.Cleanup(server.Close)
		state.manufacturer = "Supermicro"
		state.model = "X10SDV-TP8F"

		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })
		client.config = &Config{Address: "127.0.0.1", Port: 443}
		client.openIPMISession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			return newFakeIPMISession(), nil
		}

		if err := client.SetBootDevice(context.Background(), BootDevicePXE, false); err != nil {
			t.Fatalf("SetBootDevice(PXE) error: %v", err)
		}
		if state.bootTarget != "Hdd" {
			t.Errorf("PATCH target = %q, want the mock's untouched initial Hdd (OEM override is authoritative)", state.bootTarget)
		}
	})

	t.Run("Supermicro: OEM disable failure still PATCHes, then reports the failure", func(t *testing.T) {
		server, state := mockRedfishServer(t)
		t.Cleanup(server.Close)
		state.manufacturer = "Supermicro"
		state.model = "X10SDV-TP8F"
		state.bootTarget = "UefiUsbCd"
		state.bootEnabled = bootOverrideContinuous

		fake := newFakeIPMISession()
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = errors.New("completion code 0x80")
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })
		client.config = &Config{Address: "127.0.0.1", Port: 443}
		client.openIPMISession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			return fake, nil
		}

		err := client.SetBootDevice(context.Background(), BootDeviceNone, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if state.bootTarget != "None" || state.bootEnabled != bootOverrideDisabled {
			t.Errorf("PATCH must still run on a clear after an OEM wire error; got (%q, %q)", state.bootTarget, state.bootEnabled)
		}
	})

	t.Run("Supermicro: OEM PXE failure aborts before the PATCH", func(t *testing.T) {
		server, state := mockRedfishServer(t)
		t.Cleanup(server.Close)
		state.manufacturer = "Supermicro"
		state.model = "X10SDV-TP8F"

		fake := newFakeIPMISession()
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = errors.New("completion code 0x80")
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })
		client.config = &Config{Address: "127.0.0.1", Port: 443}
		client.openIPMISession = func(_ context.Context, _ *Config, _ *slog.Logger) (ipmiSession, error) {
			return fake, nil
		}

		err := client.SetBootDevice(context.Background(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if state.bootTarget != "Hdd" {
			t.Errorf("PATCH must not run after an OEM wire error on a boot target; bootTarget = %q", state.bootTarget)
		}
	})
}

// TestBootOverrideEnabled pins the BootSourceOverrideEnabled selection.
func TestBootOverrideEnabled(t *testing.T) {
	cases := []struct {
		name            string
		device          BootDevice
		persistent      bool
		forceContinuous bool
		want            string
	}{
		{"once", BootDevicePXE, false, false, bootOverrideOnce},
		{"persistent", BootDevicePXE, true, false, bootOverrideContinuous},
		{"quirk forces continuous", BootDeviceCDROM, false, true, bootOverrideContinuous},
		{"none is disabled", BootDeviceNone, false, false, bootOverrideDisabled},
		{"none ignores persistent", BootDeviceNone, true, false, bootOverrideDisabled},
		{"none ignores quirk forcing", BootDeviceNone, false, true, bootOverrideDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bootOverrideEnabled(tc.device, tc.persistent, tc.forceContinuous); got != tc.want {
				t.Errorf("bootOverrideEnabled(%q, %v, %v) = %q, want %q", tc.device, tc.persistent, tc.forceContinuous, got, tc.want)
			}
		})
	}
}

// --- System Info Tests ---

func TestRedfishClient_GetSystemInfo(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("successful system info", func(t *testing.T) {
		state.powerState = "On"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		info, err := client.GetSystemInfo(context.Background())
		if err != nil {
			t.Fatalf("GetSystemInfo() error: %v", err)
		}
		if info.Manufacturer != "TestVendor" {
			t.Errorf("Manufacturer = %q, want TestVendor", info.Manufacturer)
		}
		if info.Product != "TestServer 1000" {
			t.Errorf("Product = %q, want TestServer 1000", info.Product)
		}
		if info.SerialNumber != "SN123456" {
			t.Errorf("SerialNumber = %q, want SN123456", info.SerialNumber)
		}
		if info.BIOSVersion != "2.1.0" {
			t.Errorf("BIOSVersion = %q, want 2.1.0", info.BIOSVersion)
		}
		if info.PowerState != PowerStateOn {
			t.Errorf("PowerState = %q, want %q", info.PowerState, PowerStateOn)
		}
	})

	t.Run("system info closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		_, err := client.GetSystemInfo(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
		var target ErrInventory
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInventory, got %T: %v", err, err)
		}
	})
}

// --- Sensor Tests ---

func TestRedfishClient_GetSensors(t *testing.T) {
	server, _ := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("successful sensor read", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		sensors, err := client.GetSensors(context.Background())
		if err != nil {
			t.Fatalf("GetSensors() error: %v", err)
		}

		// Expected: 2 temps + 2 fans + 1 power control + 2 PSUs = 7
		if len(sensors) != 7 {
			t.Fatalf("got %d sensors, want 7", len(sensors))
		}

		// Check first temperature sensor.
		if sensors[0].Name != "CPU1 Temp" {
			t.Errorf("sensors[0].Name = %q, want CPU1 Temp", sensors[0].Name)
		}
		if sensors[0].Value != 42.5 {
			t.Errorf("sensors[0].Value = %f, want 42.5", sensors[0].Value)
		}
		if sensors[0].Units != "degrees C" {
			t.Errorf("sensors[0].Units = %q, want degrees C", sensors[0].Units)
		}
		if sensors[0].Status != "ok" {
			t.Errorf("sensors[0].Status = %q, want ok", sensors[0].Status)
		}

		// Check a fan sensor.
		if sensors[2].Name != "Fan1" {
			t.Errorf("sensors[2].Name = %q, want Fan1", sensors[2].Name)
		}
		if sensors[2].Value != 8500 {
			t.Errorf("sensors[2].Value = %f, want 8500", sensors[2].Value)
		}

		// Check fan with warning status.
		if sensors[3].Status != "warning" {
			t.Errorf("sensors[3].Status = %q, want warning", sensors[3].Status)
		}

		// Check power control.
		if sensors[4].Name != "Server Power" {
			t.Errorf("sensors[4].Name = %q, want Server Power", sensors[4].Name)
		}
		if sensors[4].Value != 350 {
			t.Errorf("sensors[4].Value = %f, want 350", sensors[4].Value)
		}
	})

	t.Run("sensor read closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		_, err := client.GetSensors(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
		var target ErrSensorRead
		if !errors.As(err, &target) {
			t.Errorf("expected ErrSensorRead, got %T: %v", err, err)
		}
	})
}

// --- Virtual Media Tests ---

func TestRedfishClient_MountISO(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("successful mount", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.MountISO(context.Background(), "https://example.com/boot.iso")
		if err != nil {
			t.Fatalf("MountISO() error: %v", err)
		}
		if !state.inserted {
			t.Error("expected inserted = true after mount")
		}
		if state.imageURL != "https://example.com/boot.iso" {
			t.Errorf("imageURL = %q, want https://example.com/boot.iso", state.imageURL)
		}
	})

	t.Run("mount empty URL", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.MountISO(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ISO URL")
		}
		var target ErrVirtualMedia
		if !errors.As(err, &target) {
			t.Errorf("expected ErrVirtualMedia, got %T: %v", err, err)
		}
	})

	t.Run("mount closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		err := client.MountISO(context.Background(), "https://example.com/boot.iso")
		if err == nil {
			t.Fatal("expected error for closed client")
		}
	})
}

func TestRedfishClient_UnmountISO(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("successful unmount", func(t *testing.T) {
		state.inserted = true
		state.imageURL = "https://example.com/boot.iso"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.UnmountISO(context.Background())
		if err != nil {
			t.Fatalf("UnmountISO() error: %v", err)
		}
		if state.inserted {
			t.Error("expected inserted = false after unmount")
		}
		if state.imageURL != "" {
			t.Errorf("imageURL = %q, want empty", state.imageURL)
		}
	})

	t.Run("unmount closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		err := client.UnmountISO(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
	})

	// X10 hardware quirk: after the IPMI eject path runs, the BMC
	// clears the VirtualMedia collection. The follow-on Redfish
	// best-effort unmount must treat this as success rather than
	// flagging "redfish collection VirtualMedia has no members" as
	// an error on every node post-deploy.
	t.Run("empty VirtualMedia collection is success (already unmounted)", func(t *testing.T) {
		emptyMux := http.NewServeMux()
		emptyMux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/redfish/v1/" {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, redfishServiceRoot{
				Systems:  redfishRef{ODataID: "/redfish/v1/Systems"},
				Chassis:  redfishRef{ODataID: "/redfish/v1/Chassis"},
				Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
			})
		})
		emptyMux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Systems/1"}}})
		})
		emptyMux.HandleFunc("/redfish/v1/Systems/1", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, redfishSystem{Manufacturer: "TestVendor"})
		})
		emptyMux.HandleFunc("/redfish/v1/Chassis", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Chassis/1"}}})
		})
		emptyMux.HandleFunc("/redfish/v1/Chassis/1", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, struct{}{})
		})
		emptyMux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}}})
		})
		emptyMux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, struct {
				VirtualMedia redfishRef `json:"VirtualMedia"`
			}{
				VirtualMedia: redfishRef{ODataID: "/redfish/v1/Managers/1/VirtualMedia"},
			})
		})
		// The collection exists but contains zero members.
		emptyMux.HandleFunc("/redfish/v1/Managers/1/VirtualMedia", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, redfishCollection{Members: []redfishRef{}})
		})

		emptyServer := httptest.NewServer(emptyMux)
		t.Cleanup(emptyServer.Close)

		client := newTestRedfishClient(t, emptyServer)
		t.Cleanup(func() { client.Close() })

		if err := client.UnmountISO(context.Background()); err != nil {
			t.Fatalf("UnmountISO with empty VirtualMedia collection should be no-op success, got: %v", err)
		}
	})
}

func TestRedfishClient_VirtualMediaStatus(t *testing.T) {
	server, state := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("media inserted", func(t *testing.T) {
		state.inserted = true
		state.imageURL = "https://example.com/boot.iso"
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		info, err := client.VirtualMediaStatus(context.Background())
		if err != nil {
			t.Fatalf("VirtualMediaStatus() error: %v", err)
		}
		if !info.Mounted {
			t.Error("expected Mounted = true")
		}
		if info.ImageURL != "https://example.com/boot.iso" {
			t.Errorf("ImageURL = %q, want https://example.com/boot.iso", info.ImageURL)
		}
		if info.MediaType != "cd" {
			t.Errorf("MediaType = %q, want cd", info.MediaType)
		}
	})

	t.Run("media not inserted", func(t *testing.T) {
		state.inserted = false
		state.imageURL = ""
		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		info, err := client.VirtualMediaStatus(context.Background())
		if err != nil {
			t.Fatalf("VirtualMediaStatus() error: %v", err)
		}
		if info.Mounted {
			t.Error("expected Mounted = false")
		}
	})

	t.Run("virtual media status closed client", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		_, err := client.VirtualMediaStatus(context.Background())
		if err == nil {
			t.Fatal("expected error for closed client")
		}
	})
}

// --- Close Tests ---

func TestRedfishClient_Close(t *testing.T) {
	server, _ := mockRedfishServer(t)
	t.Cleanup(server.Close)

	t.Run("close returns nil", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		err := client.Close()
		if err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	})

	t.Run("double close is idempotent", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		err := client.Close()
		if err != nil {
			t.Fatalf("first Close() error: %v", err)
		}
		err = client.Close()
		if err != nil {
			t.Fatalf("second Close() error: %v", err)
		}
	})

	t.Run("operations after close return error", func(t *testing.T) {
		client := newTestRedfishClient(t, server)
		client.Close()

		ctx := context.Background()

		if _, err := client.PowerStatus(ctx); err == nil {
			t.Error("PowerStatus should fail after close")
		}
		if err := client.PowerOn(ctx); err == nil {
			t.Error("PowerOn should fail after close")
		}
		if err := client.PowerOff(ctx); err == nil {
			t.Error("PowerOff should fail after close")
		}
		if err := client.PowerReset(ctx); err == nil {
			t.Error("PowerReset should fail after close")
		}
		if err := client.PowerCycle(ctx); err == nil {
			t.Error("PowerCycle should fail after close")
		}
		if _, err := client.GetBootDevice(ctx); err == nil {
			t.Error("GetBootDevice should fail after close")
		}
		if err := client.SetBootDevice(ctx, BootDevicePXE, false); err == nil {
			t.Error("SetBootDevice should fail after close")
		}
		if _, err := client.GetSystemInfo(ctx); err == nil {
			t.Error("GetSystemInfo should fail after close")
		}
		if _, err := client.GetSensors(ctx); err == nil {
			t.Error("GetSensors should fail after close")
		}
		if err := client.MountISO(ctx, "http://example.com/boot.iso"); err == nil {
			t.Error("MountISO should fail after close")
		}
		if err := client.UnmountISO(ctx); err == nil {
			t.Error("UnmountISO should fail after close")
		}
		if _, err := client.VirtualMediaStatus(ctx); err == nil {
			t.Error("VirtualMediaStatus should fail after close")
		}
	})
}

// --- HTTP Error Handling Tests ---

func TestRedfishClient_HTTPErrorHandling(t *testing.T) {
	t.Run("server returns 500 with Redfish error body", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(redfishError{
				Error: struct {
					Code         string                `json:"code"`
					Message      string                `json:"message"`
					ExtendedInfo []redfishExtendedInfo `json:"@Message.ExtendedInfo"`
				}{
					Code:    "Base.1.0.GeneralError",
					Message: "internal server error occurred",
				},
			})
		})
		server := httptest.NewTLSServer(mux)
		t.Cleanup(server.Close)

		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.discover(context.Background())
		if err == nil {
			t.Fatal("expected error for 500 response")
		}
		if !strings.Contains(err.Error(), "internal server error occurred") {
			t.Errorf("error message should contain Redfish error message, got: %v", err)
		}
	})

	t.Run("server returns 401 unauthorized", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		})
		server := httptest.NewTLSServer(mux)
		t.Cleanup(server.Close)

		client := newTestRedfishClient(t, server)
		t.Cleanup(func() { client.Close() })

		err := client.discover(context.Background())
		if err == nil {
			t.Fatal("expected error for 401 response")
		}
		var reqErr ErrRedfishRequest
		if errors.As(err, &reqErr) {
			if reqErr.StatusCode != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", reqErr.StatusCode)
			}
		}
	})
}

// --- Normalize Health Tests ---

func TestNormalizeRedfishHealth(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"OK", "ok"},
		{"Warning", "warning"},
		{"Critical", "critical"},
		{"", "ok"},
		{"Unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeRedfishHealth(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRedfishHealth(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Context Cancellation Tests ---

func TestRedfishClient_ContextCancellation(t *testing.T) {
	server, _ := mockRedfishServer(t)
	t.Cleanup(server.Close)

	client := newTestRedfishClient(t, server)
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := client.PowerStatus(ctx)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
}
