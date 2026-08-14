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

package container

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMeasurementEventType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		event    MeasurementEventType
		expected bool
	}{
		{
			name:     "Create is valid",
			event:    EventContainerCreate,
			expected: true,
		},
		{
			name:     "Start is valid",
			event:    EventContainerStart,
			expected: true,
		},
		{
			name:     "Stop is valid",
			event:    EventContainerStop,
			expected: true,
		},
		{
			name:     "Remove is valid",
			event:    EventContainerRemove,
			expected: true,
		},
		{
			name:     "Exec is valid",
			event:    EventContainerExec,
			expected: true,
		},
		{
			name:     "Config change is valid",
			event:    EventConfigChange,
			expected: true,
		},
		{
			name:     "Invalid event type",
			event:    MeasurementEventType("invalid"),
			expected: false,
		},
		{
			name:     "Empty event type",
			event:    MeasurementEventType(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.IsValid(); got != tt.expected {
				t.Errorf("MeasurementEventType.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewThreadSafeMeasurementLog(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	if log == nil {
		t.Fatal("NewThreadSafeMeasurementLog() returned nil")
	}

	if log.Len() != 0 {
		t.Errorf("NewThreadSafeMeasurementLog().Len() = %d, want 0", log.Len())
	}

	if !log.IsEmpty() {
		t.Error("NewThreadSafeMeasurementLog().IsEmpty() = false, want true")
	}

	entries := log.GetEntries()
	if len(entries) != 0 {
		t.Errorf("NewThreadSafeMeasurementLog().GetEntries() length = %d, want 0", len(entries))
	}
}

func TestFromMeasurementLog(t *testing.T) {
	t.Run("From nil log", func(t *testing.T) {
		log := FromMeasurementLog(nil)
		if log == nil {
			t.Fatal("FromMeasurementLog(nil) returned nil")
		}
		if log.Len() != 0 {
			t.Errorf("FromMeasurementLog(nil).Len() = %d, want 0", log.Len())
		}
	})

	t.Run("From existing log", func(t *testing.T) {
		hash := make([]byte, SHA256Size)
		existing := &MeasurementLog{
			Entries: []MeasurementEntry{
				{
					ContainerID:    "container-1",
					ContainerName:  "test",
					EventType:      EventContainerCreate,
					CumulativeHash: hash,
				},
			},
		}

		log := FromMeasurementLog(existing)
		if log.Len() != 1 {
			t.Errorf("FromMeasurementLog().Len() = %d, want 1", log.Len())
		}
	})
}

func TestThreadSafeMeasurementLog_ToMeasurementLog(t *testing.T) {
	log := NewThreadSafeMeasurementLog()
	entry := NewMeasurementEntry("container-1", "test", EventContainerCreate, "", "", "test")
	if err := log.AppendEntry(entry); err != nil {
		t.Fatalf("AppendEntry() error = %v", err)
	}

	result := log.ToMeasurementLog()
	if len(result.Entries) != 1 {
		t.Errorf("ToMeasurementLog().Entries length = %d, want 1", len(result.Entries))
	}

	// Verify it's a copy
	result.Entries[0].ContainerID = "modified"
	original := log.GetEntries()
	if original[0].ContainerID == "modified" {
		t.Error("ToMeasurementLog() returned reference instead of copy")
	}
}

func TestThreadSafeMeasurementLog_AppendEntry(t *testing.T) {
	log := NewThreadSafeMeasurementLog()
	hash := make([]byte, SHA256Size)

	entry := &MeasurementEntry{
		ContainerID:    "test-container-1",
		ContainerName:  "test",
		EventType:      EventContainerCreate,
		CumulativeHash: hash,
	}

	err := log.AppendEntry(entry)
	if err != nil {
		t.Fatalf("AppendEntry() error = %v", err)
	}

	if log.Len() != 1 {
		t.Errorf("After AppendEntry, Len() = %d, want 1", log.Len())
	}

	if log.IsEmpty() {
		t.Error("After AppendEntry, IsEmpty() = true, want false")
	}
}

func TestThreadSafeMeasurementLog_AppendEntry_Errors(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	t.Run("Nil entry", func(t *testing.T) {
		err := log.AppendEntry(nil)
		if err == nil {
			t.Error("AppendEntry(nil) should return error")
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		entry := &MeasurementEntry{
			ContainerID:    "",
			CumulativeHash: make([]byte, SHA256Size),
		}
		err := log.AppendEntry(entry)
		if err == nil {
			t.Error("AppendEntry with empty ContainerID should return error")
		}
	})

	t.Run("Invalid cumulative hash length", func(t *testing.T) {
		entry := &MeasurementEntry{
			ContainerID:    "test-container",
			CumulativeHash: make([]byte, 16), // Wrong size
		}
		err := log.AppendEntry(entry)
		if err == nil {
			t.Error("AppendEntry with invalid hash length should return error")
		}
	})

	t.Run("Empty cumulative hash", func(t *testing.T) {
		entry := &MeasurementEntry{
			ContainerID:    "test-container",
			CumulativeHash: nil,
		}
		err := log.AppendEntry(entry)
		if err == nil {
			t.Error("AppendEntry with nil hash should return error")
		}
	})
}

func TestThreadSafeMeasurementLog_AppendEntry_SetsTimestamp(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	entry := &MeasurementEntry{
		ContainerID:    "test-container",
		EventType:      EventContainerCreate,
		CumulativeHash: make([]byte, SHA256Size),
		// Timestamp intentionally not set
	}

	before := time.Now()
	err := log.AppendEntry(entry)
	after := time.Now()

	if err != nil {
		t.Fatalf("AppendEntry() error = %v", err)
	}

	entries := log.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	ts := entries[0].Timestamp
	if ts.Before(before) || ts.After(after) {
		t.Errorf("Timestamp %v not in range [%v, %v]", ts, before, after)
	}
}

func TestThreadSafeMeasurementLog_FindEntry(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	// Add multiple entries for different containers
	containers := []string{"container-1", "container-2", "container-3"}
	for _, id := range containers {
		entry := NewMeasurementEntry(id, id+"-name", EventContainerCreate, "", "", "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("Failed to append entry: %v", err)
		}
	}

	// Add a second entry for container-1
	entry := NewMeasurementEntry("container-1", "container-1-name", EventContainerStart, "", "", "")
	if err := log.AppendEntry(entry); err != nil {
		t.Fatalf("Failed to append entry: %v", err)
	}

	t.Run("Find existing container", func(t *testing.T) {
		found, err := log.FindEntry("container-2")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		if found.ContainerID != "container-2" {
			t.Errorf("FindEntry() ContainerID = %v, want container-2", found.ContainerID)
		}
	})

	t.Run("Find most recent entry", func(t *testing.T) {
		found, err := log.FindEntry("container-1")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		// Should find the START event, not CREATE
		if found.EventType != EventContainerStart {
			t.Errorf("FindEntry() returned EventType = %v, want container_start", found.EventType)
		}
	})

	t.Run("Container not found", func(t *testing.T) {
		_, err := log.FindEntry("nonexistent")
		if err == nil {
			t.Error("FindEntry() should return error for nonexistent container")
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		_, err := log.FindEntry("")
		if err == nil {
			t.Error("FindEntry() should return error for empty container ID")
		}
	})
}

func TestThreadSafeMeasurementLog_FindEntriesByContainer(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	// Add multiple entries for the same container
	containerID := "test-container"
	events := []MeasurementEventType{
		EventContainerCreate,
		EventContainerStart,
		EventContainerStop,
		EventContainerStart,
	}

	for _, event := range events {
		entry := NewMeasurementEntry(containerID, "test", event, "", "", "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("Failed to append entry: %v", err)
		}
	}

	// Add entry for different container
	other := NewMeasurementEntry("other-container", "other", EventContainerCreate, "", "", "")
	if err := log.AppendEntry(other); err != nil {
		t.Fatalf("Failed to append entry: %v", err)
	}

	t.Run("Find all entries for container", func(t *testing.T) {
		entries, err := log.FindEntriesByContainer(containerID)
		if err != nil {
			t.Fatalf("FindEntriesByContainer() error = %v", err)
		}
		if len(entries) != 4 {
			t.Errorf("FindEntriesByContainer() returned %d entries, want 4", len(entries))
		}

		// Verify chronological order
		for i, expected := range events {
			if entries[i].EventType != expected {
				t.Errorf("Entry %d EventType = %v, want %v", i, entries[i].EventType, expected)
			}
		}
	})

	t.Run("Container with no entries", func(t *testing.T) {
		entries, err := log.FindEntriesByContainer("nonexistent")
		if err != nil {
			t.Fatalf("FindEntriesByContainer() error = %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("FindEntriesByContainer() returned %d entries, want 0", len(entries))
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		_, err := log.FindEntriesByContainer("")
		if err == nil {
			t.Error("FindEntriesByContainer() should return error for empty container ID")
		}
	})
}

func TestThreadSafeMeasurementLog_GetEntries(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	// Add some entries
	for i := 0; i < 3; i++ {
		entry := NewMeasurementEntry("container-"+string(rune('A'+i)), "name", EventContainerCreate, "", "", "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("Failed to append entry: %v", err)
		}
	}

	entries := log.GetEntries()

	t.Run("Returns correct count", func(t *testing.T) {
		if len(entries) != 3 {
			t.Errorf("GetEntries() returned %d entries, want 3", len(entries))
		}
	})

	t.Run("Returns copy not reference", func(t *testing.T) {
		// Modify returned slice
		entries[0].ContainerID = "modified"

		// Original should be unchanged
		original := log.GetEntries()
		if original[0].ContainerID == "modified" {
			t.Error("GetEntries() returned reference instead of copy")
		}
	})
}

func TestThreadSafeMeasurementLog_ComputeExpectedPCR(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	t.Run("Empty log returns zeros", func(t *testing.T) {
		pcr := log.ComputeExpectedPCR()
		if len(pcr) != SHA256Size {
			t.Fatalf("ComputeExpectedPCR() returned %d bytes, want %d", len(pcr), SHA256Size)
		}

		// All zeros
		zeros := make([]byte, SHA256Size)
		if !bytes.Equal(pcr, zeros) {
			t.Error("ComputeExpectedPCR() should return zeros for empty log")
		}
	})

	t.Run("Single entry extends from zeros", func(t *testing.T) {
		hash := sha256.Sum256([]byte("test"))
		entry := &MeasurementEntry{
			ContainerID:    "test",
			CumulativeHash: hash[:],
		}
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		pcr := log.ComputeExpectedPCR()

		// Manual computation: SHA256(zeros || hash)
		zeros := make([]byte, SHA256Size)
		expected := sha256.Sum256(append(zeros, hash[:]...))

		if !bytes.Equal(pcr, expected[:]) {
			t.Error("ComputeExpectedPCR() returned unexpected value")
		}
	})

	t.Run("Multiple entries chain correctly", func(t *testing.T) {
		log2 := NewThreadSafeMeasurementLog()

		hash1 := sha256.Sum256([]byte("entry1"))
		hash2 := sha256.Sum256([]byte("entry2"))

		entry1 := &MeasurementEntry{
			ContainerID:    "container1",
			CumulativeHash: hash1[:],
		}
		entry2 := &MeasurementEntry{
			ContainerID:    "container2",
			CumulativeHash: hash2[:],
		}

		if err := log2.AppendEntry(entry1); err != nil {
			t.Fatalf("AppendEntry(1) error = %v", err)
		}
		if err := log2.AppendEntry(entry2); err != nil {
			t.Fatalf("AppendEntry(2) error = %v", err)
		}

		pcr := log2.ComputeExpectedPCR()

		// Manual computation
		zeros := make([]byte, SHA256Size)
		intermediate := sha256.Sum256(append(zeros, hash1[:]...))
		expected := sha256.Sum256(append(intermediate[:], hash2[:]...))

		if !bytes.Equal(pcr, expected[:]) {
			t.Error("ComputeExpectedPCR() chain computation incorrect")
		}
	})
}

func TestThreadSafeMeasurementLog_ComputeExpectedPCRUpToEntry(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	hashes := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		hashes[i] = h[:]
		entry := &MeasurementEntry{
			ContainerID:    "container",
			CumulativeHash: hashes[i],
		}
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry(%d) error = %v", i, err)
		}
	}

	t.Run("Index 0", func(t *testing.T) {
		pcr, err := log.ComputeExpectedPCRUpToEntry(0)
		if err != nil {
			t.Fatalf("ComputeExpectedPCRUpToEntry(0) error = %v", err)
		}

		zeros := make([]byte, SHA256Size)
		expected := sha256.Sum256(append(zeros, hashes[0]...))
		if !bytes.Equal(pcr, expected[:]) {
			t.Error("ComputeExpectedPCRUpToEntry(0) returned unexpected value")
		}
	})

	t.Run("Index 2", func(t *testing.T) {
		pcr, err := log.ComputeExpectedPCRUpToEntry(2)
		if err != nil {
			t.Fatalf("ComputeExpectedPCRUpToEntry(2) error = %v", err)
		}

		// Manual computation through index 2
		current := make([]byte, SHA256Size)
		for i := 0; i <= 2; i++ {
			h := sha256.New()
			h.Write(current)
			h.Write(hashes[i])
			current = h.Sum(nil)
		}

		if !bytes.Equal(pcr, current) {
			t.Error("ComputeExpectedPCRUpToEntry(2) returned unexpected value")
		}
	})

	t.Run("Last index equals full computation", func(t *testing.T) {
		pcrPartial, err := log.ComputeExpectedPCRUpToEntry(4)
		if err != nil {
			t.Fatalf("ComputeExpectedPCRUpToEntry(4) error = %v", err)
		}

		pcrFull := log.ComputeExpectedPCR()
		if !bytes.Equal(pcrPartial, pcrFull) {
			t.Error("ComputeExpectedPCRUpToEntry(last) != ComputeExpectedPCR()")
		}
	})

	t.Run("Invalid index negative", func(t *testing.T) {
		_, err := log.ComputeExpectedPCRUpToEntry(-1)
		if err == nil {
			t.Error("ComputeExpectedPCRUpToEntry(-1) should return error")
		}
	})

	t.Run("Invalid index too large", func(t *testing.T) {
		_, err := log.ComputeExpectedPCRUpToEntry(100)
		if err == nil {
			t.Error("ComputeExpectedPCRUpToEntry(100) should return error")
		}
	})
}

func TestThreadSafeMeasurementLog_Clear(t *testing.T) {
	log := NewThreadSafeMeasurementLog()

	// Add some entries
	for i := 0; i < 3; i++ {
		entry := NewMeasurementEntry("container", "name", EventContainerCreate, "", "", "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}
	}

	if log.Len() != 3 {
		t.Fatalf("Expected 3 entries before clear, got %d", log.Len())
	}

	log.Clear()

	if log.Len() != 0 {
		t.Errorf("After Clear(), Len() = %d, want 0", log.Len())
	}

	if !log.IsEmpty() {
		t.Error("After Clear(), IsEmpty() = false, want true")
	}
}

func TestThreadSafeMeasurementLog_PersistAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "measurement_log.json")

	log := NewThreadSafeMeasurementLog()

	// Add entries
	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	entry1 := NewMeasurementEntry("container-1", "name1", EventContainerCreate, imageDigest, configDigest, "created")
	entry2 := NewMeasurementEntry("container-1", "name1", EventContainerStart, "", "", "started")
	entry3 := NewMeasurementEntry("container-2", "name2", EventContainerCreate, imageDigest, "", "created")

	for _, entry := range []*MeasurementEntry{entry1, entry2, entry3} {
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}
	}

	// Persist
	if err := log.Persist(logPath); err != nil {
		t.Fatalf("Persist() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("Log file not created: %v", err)
	}

	// Load
	loaded, err := LoadThreadSafeMeasurementLog(logPath)
	if err != nil {
		t.Fatalf("LoadThreadSafeMeasurementLog() error = %v", err)
	}

	// Verify loaded data
	if loaded.Len() != log.Len() {
		t.Errorf("Loaded log length = %d, want %d", loaded.Len(), log.Len())
	}

	origEntries := log.GetEntries()
	loadedEntries := loaded.GetEntries()

	for i := range origEntries {
		if origEntries[i].ContainerID != loadedEntries[i].ContainerID {
			t.Errorf("Entry %d ContainerID mismatch", i)
		}
		if origEntries[i].EventType != loadedEntries[i].EventType {
			t.Errorf("Entry %d EventType mismatch", i)
		}
		if !bytes.Equal(origEntries[i].CumulativeHash, loadedEntries[i].CumulativeHash) {
			t.Errorf("Entry %d CumulativeHash mismatch", i)
		}
	}

	// Verify PCR computation matches
	origPCR := log.ComputeExpectedPCR()
	loadedPCR := loaded.ComputeExpectedPCR()
	if !bytes.Equal(origPCR, loadedPCR) {
		t.Error("Loaded log produces different PCR value")
	}
}

func TestThreadSafeMeasurementLog_Persist_Errors(t *testing.T) {
	log := NewThreadSafeMeasurementLog()
	entry := NewMeasurementEntry("container", "name", EventContainerCreate, "", "", "")
	if err := log.AppendEntry(entry); err != nil {
		t.Fatalf("AppendEntry() error = %v", err)
	}

	t.Run("Empty path", func(t *testing.T) {
		err := log.Persist("")
		if err == nil {
			t.Error("Persist('') should return error")
		}
	})
}

func TestLoadThreadSafeMeasurementLog_Errors(t *testing.T) {
	t.Run("Empty path", func(t *testing.T) {
		_, err := LoadThreadSafeMeasurementLog("")
		if err == nil {
			t.Error("LoadThreadSafeMeasurementLog('') should return error")
		}
	})

	t.Run("Nonexistent file", func(t *testing.T) {
		_, err := LoadThreadSafeMeasurementLog("/nonexistent/path/file.json")
		if err == nil {
			t.Error("LoadThreadSafeMeasurementLog(nonexistent) should return error")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "invalid.json")
		if err := os.WriteFile(path, []byte("not valid json"), 0600); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		_, err := LoadThreadSafeMeasurementLog(path)
		if err == nil {
			t.Error("LoadThreadSafeMeasurementLog(invalid JSON) should return error")
		}
	})
}

// TestLoadThreadSafeMeasurementLog_IgnoresStaleVersionKey asserts the loader
// carries no format gate: a file left over from an earlier build that still
// carries a "version" key loads normally and replays to the same PCR. There is
// exactly one measurement log format, so an unknown key is simply ignored.
func TestLoadThreadSafeMeasurementLog_IgnoresStaleVersionKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.json")

	log := NewThreadSafeMeasurementLog()
	entry := NewMeasurementEntry("container-1", "name1", EventContainerCreate,
		digestOf("image"), digestOf("config"), "created")
	if err := log.AppendEntry(entry); err != nil {
		t.Fatalf("AppendEntry() error = %v", err)
	}
	if err := log.Persist(path); err != nil {
		t.Fatalf("Persist() error = %v", err)
	}

	jsonData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(jsonData, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if _, ok := raw["version"]; ok {
		t.Error("Persist() must not write a version key")
	}
	raw["version"] = 1
	stale, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, stale, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	loaded, err := LoadThreadSafeMeasurementLog(path)
	if err != nil {
		t.Fatalf("LoadThreadSafeMeasurementLog() error = %v", err)
	}
	if loaded.Len() != 1 {
		t.Fatalf("Loaded log length = %d, want 1", loaded.Len())
	}
	if !bytes.Equal(loaded.ComputeExpectedPCR(), log.ComputeExpectedPCR()) {
		t.Error("Loaded log produces different PCR value")
	}
}

func TestComputeEntryHash(t *testing.T) {
	containerID := "test-container"
	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	t.Run("Deterministic", func(t *testing.T) {
		hash1 := ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerCreate)
		hash2 := ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerCreate)

		if !bytes.Equal(hash1, hash2) {
			t.Error("ComputeEntryHash() not deterministic")
		}
	})

	t.Run("Different container IDs produce different hashes", func(t *testing.T) {
		hash1 := ComputeEntryHash("container-1", imageDigest, configDigest, EventContainerCreate)
		hash2 := ComputeEntryHash("container-2", imageDigest, configDigest, EventContainerCreate)

		if bytes.Equal(hash1, hash2) {
			t.Error("Different container IDs should produce different hashes")
		}
	})

	t.Run("Different event types produce different hashes", func(t *testing.T) {
		hash1 := ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerCreate)
		hash2 := ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerStart)

		if bytes.Equal(hash1, hash2) {
			t.Error("Different event types should produce different hashes")
		}
	})

	t.Run("Nil digests handled", func(t *testing.T) {
		hash := ComputeEntryHash(containerID, "", "", EventContainerStart)
		if len(hash) != SHA256Size {
			t.Errorf("ComputeEntryHash with nil digests returned %d bytes, want %d", len(hash), SHA256Size)
		}
	})
}

func TestNewMeasurementEntry(t *testing.T) {
	containerID := "test-container"
	containerName := "test-name"
	imageDigest := digestOf("image")
	configDigest := digestOf("config")
	description := "test description"

	entry := NewMeasurementEntry(containerID, containerName, EventContainerCreate, imageDigest, configDigest, description)

	if entry.ContainerID != containerID {
		t.Errorf("NewMeasurementEntry() ContainerID = %v, want %v", entry.ContainerID, containerID)
	}

	if entry.ContainerName != containerName {
		t.Errorf("NewMeasurementEntry() ContainerName = %v, want %v", entry.ContainerName, containerName)
	}

	if entry.EventType != EventContainerCreate {
		t.Errorf("NewMeasurementEntry() EventType = %v, want container_create", entry.EventType)
	}

	if entry.ImageDigest != imageDigest {
		t.Error("NewMeasurementEntry() ImageDigest mismatch")
	}

	if entry.ConfigDigest != configDigest {
		t.Error("NewMeasurementEntry() ConfigDigest mismatch")
	}

	if entry.Description != description {
		t.Errorf("NewMeasurementEntry() Description = %v, want %v", entry.Description, description)
	}

	if len(entry.CumulativeHash) != SHA256Size {
		t.Errorf("NewMeasurementEntry() CumulativeHash length = %d, want %d", len(entry.CumulativeHash), SHA256Size)
	}

	if entry.Timestamp.IsZero() {
		t.Error("NewMeasurementEntry() should set Timestamp")
	}

	// Verify cumulative hash is computed correctly
	expectedHash := ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerCreate)
	if !bytes.Equal(entry.CumulativeHash, expectedHash) {
		t.Error("NewMeasurementEntry() CumulativeHash != ComputeEntryHash()")
	}
}

func TestThreadSafeMeasurementLog_ConcurrentAccess(t *testing.T) {
	log := NewThreadSafeMeasurementLog()
	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			containerID := "container-" + string(rune('A'+(id%26)))
			entry := NewMeasurementEntry(containerID, "name", EventContainerCreate, "", "", "")
			if err := log.AppendEntry(entry); err != nil {
				t.Errorf("Concurrent AppendEntry failed: %v", err)
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = log.GetEntries()
			_ = log.ComputeExpectedPCR()
			_ = log.Len()
		}()
	}

	wg.Wait()

	if log.Len() != 100 {
		t.Errorf("After concurrent access, Len() = %d, want 100", log.Len())
	}
}

func TestMeasurementEntry_Validate(t *testing.T) {
	validHash := make([]byte, SHA256Size)

	tests := []struct {
		name    string
		entry   *MeasurementEntry
		wantErr bool
	}{
		{
			name: "Valid entry",
			entry: &MeasurementEntry{
				ContainerID:    "container-1",
				EventType:      EventContainerCreate,
				CumulativeHash: validHash,
			},
			wantErr: false,
		},
		{
			name: "Empty container ID",
			entry: &MeasurementEntry{
				ContainerID:    "",
				EventType:      EventContainerCreate,
				CumulativeHash: validHash,
			},
			wantErr: true,
		},
		{
			name: "Invalid event type",
			entry: &MeasurementEntry{
				ContainerID:    "container-1",
				EventType:      MeasurementEventType("invalid"),
				CumulativeHash: validHash,
			},
			wantErr: true,
		},
		{
			name: "Invalid image digest length",
			entry: &MeasurementEntry{
				ContainerID:    "container-1",
				EventType:      EventContainerCreate,
				ImageDigest:    "sha256:deadbeef", // truncated hex
				CumulativeHash: validHash,
			},
			wantErr: true,
		},
		{
			name: "Invalid config digest length",
			entry: &MeasurementEntry{
				ContainerID:    "container-1",
				EventType:      EventContainerCreate,
				ConfigDigest:   "not-a-digest",
				CumulativeHash: validHash,
			},
			wantErr: true,
		},
		{
			name: "Invalid cumulative hash length",
			entry: &MeasurementEntry{
				ContainerID:    "container-1",
				EventType:      EventContainerCreate,
				CumulativeHash: make([]byte, 16), // Wrong size
			},
			wantErr: true,
		},
		{
			name: "Empty image digest is valid",
			entry: &MeasurementEntry{
				ContainerID:    "container-1",
				EventType:      EventContainerCreate,
				ImageDigest:    "",
				CumulativeHash: validHash,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("MeasurementEntry.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestComputeExpectedPCRFromLog(t *testing.T) {
	t.Run("Nil log returns zeros", func(t *testing.T) {
		pcr := ComputeExpectedPCRFromLog(nil)
		if len(pcr) != SHA256Size {
			t.Errorf("ComputeExpectedPCRFromLog(nil) returned %d bytes, want %d", len(pcr), SHA256Size)
		}
		zeros := make([]byte, SHA256Size)
		if !bytes.Equal(pcr, zeros) {
			t.Error("ComputeExpectedPCRFromLog(nil) should return zeros")
		}
	})

	t.Run("Empty log returns zeros", func(t *testing.T) {
		log := &MeasurementLog{Entries: []MeasurementEntry{}}
		pcr := ComputeExpectedPCRFromLog(log)
		zeros := make([]byte, SHA256Size)
		if !bytes.Equal(pcr, zeros) {
			t.Error("ComputeExpectedPCRFromLog(empty) should return zeros")
		}
	})

	t.Run("Single entry", func(t *testing.T) {
		hash := sha256.Sum256([]byte("test"))
		log := &MeasurementLog{
			Entries: []MeasurementEntry{
				{
					ContainerID:    "test",
					CumulativeHash: hash[:],
				},
			},
		}
		pcr := ComputeExpectedPCRFromLog(log)
		if len(pcr) != SHA256Size {
			t.Errorf("ComputeExpectedPCRFromLog() returned %d bytes, want %d", len(pcr), SHA256Size)
		}
	})
}
