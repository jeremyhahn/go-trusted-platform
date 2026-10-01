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

package bootstrap

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

func dryRunSELConfig() *BootstrapConfig {
	return &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "10.4.6.91"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "test.local"},
		Nodes: []NodeConfig{{
			Hostname: "node-02", Role: RoleControlPlane,
			BMCAddress: "10.4.2.102", BMCUser: "admin", BMCPassword: "pass", BMCProtocol: "ipmi",
		}},
	}
}

func memoryFault(sensor string, offset uint8, at time.Time) bmc.EventLogEntry {
	return bmc.EventLogEntry{
		Timestamp: at, SensorTypeCode: bmc.SensorTypeMemory, SensorType: "Memory",
		Sensor: sensor, SensorNumber: 0x1A, EventOffset: offset, Asserted: true,
		Message: map[uint8]string{
			bmc.MemoryEventCorrectableECC:   "Correctable ECC",
			bmc.MemoryEventUncorrectableECC: "Uncorrectable ECC",
		}[offset],
	}
}

func TestOrchestrator_DryRun_EventLogWarnings(t *testing.T) {
	lastECC := time.Date(2024, 4, 20, 9, 30, 0, 0, time.UTC)
	mockClient := bmc.NewMockClient()
	mockClient.Log = &bmc.EventLog{
		FreeBytes:    0,
		LastAddition: lastECC,
		Entries: []bmc.EventLogEntry{
			memoryFault("DIMMB1", bmc.MemoryEventCorrectableECC, lastECC.Add(-time.Hour)),
			memoryFault("DIMMB1", bmc.MemoryEventCorrectableECC, lastECC),
			memoryFault("DIMMB1", bmc.MemoryEventUncorrectableECC, lastECC.Add(-2*time.Hour)),
			{SensorTypeCode: bmc.SensorTypeEventLoggingDisabled, EventOffset: bmc.LoggingEventSELFull, Asserted: true, Message: "SEL full"},
		},
	}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:     dryRunSELConfig(),
		BMCFactory: &bmc.MockClientFactory{Client: mockClient},
		Logger:     orchTestLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := o.DryRun(t.Context())
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if mockClient.GetEventLogCalls() != 1 {
		t.Fatalf("expected one SEL read, got %d", mockClient.GetEventLogCalls())
	}
	node := result.Nodes[0]
	if node.Status != dryRunStatusReady {
		t.Errorf("SEL findings must not change readiness, got %s", node.Status)
	}
	if len(node.Warnings) != 2 {
		t.Fatalf("expected a log-full warning and a DIMMB1 warning, got %q", node.Warnings)
	}
	if !strings.Contains(node.Warnings[0], "node-02: system event log is full") || !strings.Contains(node.Warnings[0], "2024-04-20T09:30:00Z") {
		t.Errorf("log-full warning: %q", node.Warnings[0])
	}
	want := "node-02: DIMMB1 has 3 memory faults on record (1 uncorrectable), last: Correctable ECC at 2024-04-20T09:30:00Z — expect POST to halt on this DIMM"
	if node.Warnings[1] != want {
		t.Errorf("DIMM warning:\n got %q\nwant %q", node.Warnings[1], want)
	}
	// Node warnings are folded into the summary the CLI prints.
	joined := strings.Join(result.Warnings, "\n")
	for _, w := range node.Warnings {
		if !strings.Contains(joined, w) {
			t.Errorf("summary warnings missing %q", w)
		}
	}
	for _, e := range result.Errors {
		if strings.Contains(e, "event log") || strings.Contains(e, "DIMM") {
			t.Errorf("SEL findings are warnings, not errors: %q", e)
		}
	}
}

func TestOrchestrator_DryRun_EventLogCleanIsSilent(t *testing.T) {
	mockClient := bmc.NewMockClient()
	mockClient.Log = &bmc.EventLog{FreeBytes: 4096, Entries: []bmc.EventLogEntry{
		{SensorTypeCode: 0x07, SensorType: "Processor", Asserted: true, Message: "Presence detected"},
		memoryFault("DIMMA1", bmc.MemoryEventPresenceDetected, time.Now()),
	}}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:     dryRunSELConfig(),
		BMCFactory: &bmc.MockClientFactory{Client: mockClient},
		Logger:     orchTestLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, err := o.DryRun(t.Context())
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if len(result.Nodes[0].Warnings) != 0 {
		t.Errorf("a healthy log must not warn, got %q", result.Nodes[0].Warnings)
	}
}

func TestOrchestrator_DryRun_EventLogUnsupportedAndUnreadable(t *testing.T) {
	t.Run("unsupported is silent", func(t *testing.T) {
		mockClient := bmc.NewMockClient()
		mockClient.GetEventLogErr = bmc.ErrUnsupportedOperation{Operation: "event log"}
		o, err := NewOrchestrator(OrchestratorParams{
			Config:     dryRunSELConfig(),
			BMCFactory: &bmc.MockClientFactory{Client: mockClient},
			Logger:     orchTestLogger(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		result, err := o.DryRun(t.Context())
		if err != nil {
			t.Fatalf("dry-run failed: %v", err)
		}
		if len(result.Nodes[0].Warnings) != 0 || result.Nodes[0].Status != dryRunStatusReady {
			t.Errorf("unsupported log must be silent and keep the node ready: %+v", result.Nodes[0])
		}
	})
	t.Run("read failure warns", func(t *testing.T) {
		mockClient := bmc.NewMockClient()
		mockClient.GetEventLogErr = bmc.ErrEventLogRead{Operation: "info", Cause: errors.New("timeout")}
		o, err := NewOrchestrator(OrchestratorParams{
			Config:     dryRunSELConfig(),
			BMCFactory: &bmc.MockClientFactory{Client: mockClient},
			Logger:     orchTestLogger(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		result, err := o.DryRun(t.Context())
		if err != nil {
			t.Fatalf("dry-run failed: %v", err)
		}
		warnings := result.Nodes[0].Warnings
		if len(warnings) != 1 || !strings.Contains(warnings[0], "node-02: system event log could not be read (bmc: event log info failed: timeout)") {
			t.Errorf("read failure warning: %q", warnings)
		}
		if result.Nodes[0].Status != dryRunStatusReady {
			t.Error("an unreadable log is a warning, not a readiness failure")
		}
	})
}

func TestEventLogWarnings_UnnamedSensorAndNoTimestamps(t *testing.T) {
	log := &bmc.EventLog{FreeBytes: -1, Overflow: true, Entries: []bmc.EventLogEntry{
		{SensorTypeCode: bmc.SensorTypeMemory, SensorNumber: 7, EventOffset: bmc.MemoryEventParity, Asserted: true, Message: "Parity"},
	}}
	got := eventLogWarnings("w1", log)
	if len(got) != 2 {
		t.Fatalf("expected 2 warnings, got %q", got)
	}
	if got[0] != "w1: system event log is full — new hardware faults will not be recorded; clear the SEL before provisioning" {
		t.Errorf("overflow warning without timestamp: %q", got[0])
	}
	if got[1] != "w1: sensor 7 has 1 memory fault on record (1 uncorrectable), last: Parity — expect POST to halt on this DIMM" {
		t.Errorf("unnamed sensor warning: %q", got[1])
	}
	if eventLogWarnings("w1", &bmc.EventLog{FreeBytes: -1}) != nil {
		t.Error("an empty log yields no warnings")
	}
	truncated := eventLogWarnings("w1", &bmc.EventLog{FreeBytes: -1, Truncated: true, EntryCount: 9000,
		Entries: make([]bmc.EventLogEntry, 4096)})
	if len(truncated) != 1 || truncated[0] != "w1: system event log read stopped at 4096 of 9000 entries — faults in the unread part are not reported" {
		t.Errorf("truncation warning: %q", truncated)
	}
}
