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
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SHA256Size is the size of a SHA-256 hash in bytes.
const SHA256Size = 32

// DefaultPCRIndex is the default PCR index used for container attestation.
// WorkloadPCR (default: 14) is used as the aggregate hash for all container measurements.
// This value can be overridden via configuration.
const DefaultPCRIndex = 14

// MeasurementEventType represents the type of container lifecycle event
// that was measured.
type MeasurementEventType string

const (
	// EventContainerCreate is recorded when a container is created.
	EventContainerCreate MeasurementEventType = "container_create"

	// EventContainerStart is recorded when a container is started.
	EventContainerStart MeasurementEventType = "container_start"

	// EventContainerStop is recorded when a container is stopped.
	EventContainerStop MeasurementEventType = "container_stop"

	// EventContainerRemove is recorded when a container is removed.
	EventContainerRemove MeasurementEventType = "container_remove"

	// EventContainerExec is recorded when a command is executed in a container.
	EventContainerExec MeasurementEventType = "container_exec"

	// EventConfigChange is recorded when container configuration changes.
	EventConfigChange MeasurementEventType = "config_change"
)

// IsValid checks if the event type is valid.
func (e MeasurementEventType) IsValid() bool {
	switch e {
	case EventContainerCreate, EventContainerStart, EventContainerStop,
		EventContainerRemove, EventContainerExec, EventConfigChange:
		return true
	default:
		return false
	}
}

// MeasurementEntry represents a single measurement event in the log.
type MeasurementEntry struct {
	// ContainerID is the unique identifier of the container.
	ContainerID string `json:"container_id"`

	// ContainerName is the human-readable name of the container.
	ContainerName string `json:"container_name"`

	// Timestamp is when the measurement was recorded.
	Timestamp time.Time `json:"timestamp"`

	// EventType indicates what container lifecycle event occurred.
	EventType MeasurementEventType `json:"event_type"`

	// ImageDigest is the SHA-256 digest of the container image.
	ImageDigest []byte `json:"image_digest,omitempty"`

	// ConfigDigest is the SHA-256 digest of the container configuration.
	ConfigDigest []byte `json:"config_digest,omitempty"`

	// CumulativeHash is the hash that was extended to the PCR.
	CumulativeHash []byte `json:"cumulative_hash"`

	// Description provides additional context about the event.
	Description string `json:"description,omitempty"`
}

// Validate validates the measurement entry.
func (e *MeasurementEntry) Validate() error {
	if e.ContainerID == "" {
		return ErrInvalidContainerID
	}
	if !e.EventType.IsValid() {
		return ErrMeasurementLogInvalid
	}
	if len(e.ImageDigest) != 0 && len(e.ImageDigest) != SHA256Size {
		return ErrMeasurementLogInvalid
	}
	if len(e.ConfigDigest) != 0 && len(e.ConfigDigest) != SHA256Size {
		return ErrMeasurementLogInvalid
	}
	if len(e.CumulativeHash) != SHA256Size {
		return ErrMeasurementLogInvalid
	}
	return nil
}

// MeasurementLog contains the full measurement log for container attestation.
type MeasurementLog struct {
	// Entries are the measurement entries in chronological order.
	Entries []MeasurementEntry `json:"entries"`
}

// ContainerSpec represents a container specification for attestation purposes.
// This is used to compute the configuration digest.
type ContainerSpec struct {
	// Name is the container name.
	Name string `json:"name"`

	// Image is the container image reference.
	Image string `json:"image"`

	// Command is the command to run in the container.
	Command []string `json:"command,omitempty"`

	// User specifies the user to run as.
	User string `json:"user,omitempty"`

	// WorkingDir is the working directory in the container.
	WorkingDir string `json:"working_dir,omitempty"`

	// Privileged indicates if the container runs in privileged mode.
	Privileged bool `json:"privileged,omitempty"`

	// Mounts are the container mounts.
	Mounts []MountSpec `json:"mounts,omitempty"`

	// Capabilities are Linux capabilities.
	Capabilities CapabilitySpec `json:"capabilities,omitempty"`

	// Environment variables.
	Environment map[string]string `json:"environment,omitempty"`
}

// MountSpec represents a mount specification for attestation.
type MountSpec struct {
	// Source is the source path on the host.
	Source string `json:"source"`

	// Target is the target path in the container.
	Target string `json:"target"`

	// Type is the mount type.
	Type string `json:"type,omitempty"`

	// ReadOnly indicates if the mount is read-only.
	ReadOnly bool `json:"read_only,omitempty"`
}

// CapabilitySpec represents capability specifications for attestation.
type CapabilitySpec struct {
	// Add are capabilities to add.
	Add []string `json:"add,omitempty"`

	// Drop are capabilities to drop.
	Drop []string `json:"drop,omitempty"`
}

// ThreadSafeMeasurementLog provides thread-safe access to a MeasurementLog.
// It wraps the MeasurementLog from orchestrator.go with mutex protection
// and provides additional methods for PCR computation and persistence.
type ThreadSafeMeasurementLog struct {
	mu      sync.RWMutex
	entries []MeasurementEntry

	// Version tracks the log format version for future compatibility.
	version int
}

// NewThreadSafeMeasurementLog creates a new empty thread-safe measurement log.
func NewThreadSafeMeasurementLog() *ThreadSafeMeasurementLog {
	return &ThreadSafeMeasurementLog{
		entries: make([]MeasurementEntry, 0),
		version: 1,
	}
}

// FromMeasurementLog creates a ThreadSafeMeasurementLog from an existing MeasurementLog.
func FromMeasurementLog(log *MeasurementLog) *ThreadSafeMeasurementLog {
	if log == nil {
		return NewThreadSafeMeasurementLog()
	}
	return &ThreadSafeMeasurementLog{
		entries: log.Entries,
		version: 1,
	}
}

// ToMeasurementLog returns the underlying MeasurementLog structure.
func (l *ThreadSafeMeasurementLog) ToMeasurementLog() *MeasurementLog {
	l.mu.RLock()
	defer l.mu.RUnlock()

	entries := make([]MeasurementEntry, len(l.entries))
	copy(entries, l.entries)
	return &MeasurementLog{
		Entries: entries,
	}
}

// AppendEntry adds a new measurement entry to the log.
// The entry must have a valid ContainerID and CumulativeHash.
func (l *ThreadSafeMeasurementLog) AppendEntry(entry *MeasurementEntry) error {
	if entry == nil {
		return NewContainerError("", "", "append_entry", ErrInvalidSpec)
	}

	if entry.ContainerID == "" {
		return ErrInvalidContainerID
	}

	if len(entry.CumulativeHash) != SHA256Size {
		return ErrMeasurementLogInvalid
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Set timestamp if not already set
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	l.entries = append(l.entries, *entry)
	return nil
}

// FindEntry finds the most recent entry for a given container ID.
// Returns ErrContainerNotFound if no entry exists for the container.
func (l *ThreadSafeMeasurementLog) FindEntry(containerID string) (*MeasurementEntry, error) {
	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	// Search in reverse order to find the most recent entry
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].ContainerID == containerID {
			entry := l.entries[i]
			return &entry, nil
		}
	}

	return nil, ErrContainerNotFound
}

// FindEntriesByContainer returns all entries for a given container ID
// in chronological order.
// Returns an empty slice if no entries exist for the container.
func (l *ThreadSafeMeasurementLog) FindEntriesByContainer(containerID string) ([]*MeasurementEntry, error) {
	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*MeasurementEntry, 0)
	for i := range l.entries {
		if l.entries[i].ContainerID == containerID {
			entry := l.entries[i]
			result = append(result, &entry)
		}
	}

	return result, nil
}

// GetEntries returns a copy of all entries in the log.
// The returned slice is a deep copy to prevent external modifications.
func (l *ThreadSafeMeasurementLog) GetEntries() []MeasurementEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]MeasurementEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// Len returns the number of entries in the log.
func (l *ThreadSafeMeasurementLog) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// IsEmpty returns true if the log has no entries.
func (l *ThreadSafeMeasurementLog) IsEmpty() bool {
	return l.Len() == 0
}

// ComputeExpectedPCR replays the measurement log to compute the expected
// PCR value. This is used during attestation verification to compare
// against the actual PCR value from a TPM quote.
//
// The PCR computation follows the standard TCG event log approach:
// - Start with PCR value of all zeros
// - For each entry: new_pcr = SHA256(old_pcr || entry.CumulativeHash)
//
// Returns the expected WorkloadPCR value after all entries have been replayed.
// Returns a zero hash if the log is empty.
func (l *ThreadSafeMeasurementLog) ComputeExpectedPCR() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Initialize PCR to zeros (initial state for WorkloadPCR)
	pcr := make([]byte, SHA256Size)

	for _, entry := range l.entries {
		pcr = extendHash(pcr, entry.CumulativeHash)
	}

	return pcr
}

// ComputeExpectedPCRUpToEntry computes the expected PCR value up to and
// including the specified entry index. This is useful for partial log
// verification.
func (l *ThreadSafeMeasurementLog) ComputeExpectedPCRUpToEntry(index int) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if index < 0 || index >= len(l.entries) {
		return nil, ErrContainerNotFound
	}

	// Initialize PCR to zeros
	pcr := make([]byte, SHA256Size)

	for i := 0; i <= index; i++ {
		pcr = extendHash(pcr, l.entries[i].CumulativeHash)
	}

	return pcr, nil
}

// Clear removes all entries from the log.
func (l *ThreadSafeMeasurementLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make([]MeasurementEntry, 0)
}

// threadSafeMeasurementLogPersisted is the on-disk format for the measurement log.
type threadSafeMeasurementLogPersisted struct {
	Version int                `json:"version"`
	Entries []MeasurementEntry `json:"entries"`
}

// Persist writes the measurement log to a file at the specified path.
// The log is written atomically by first writing to a temporary file
// and then renaming it to the target path.
func (l *ThreadSafeMeasurementLog) Persist(path string) error {
	if path == "" {
		return NewContainerError("", "", "persist", ErrInvalidSpec)
	}

	l.mu.RLock()
	data := threadSafeMeasurementLogPersisted{
		Version: l.version,
		Entries: make([]MeasurementEntry, len(l.entries)),
	}
	copy(data.Entries, l.entries)
	l.mu.RUnlock()

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return NewContainerError("", "", "persist_marshal", err)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return NewContainerError("", "", "persist_mkdir", err)
	}

	// Write to temporary file first
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, jsonData, 0600); err != nil {
		return NewContainerError("", "", "persist_write", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return NewContainerError("", "", "persist_rename", err)
	}

	return nil
}

// LoadThreadSafeMeasurementLog reads a measurement log from a file at the specified path.
// Returns a new ThreadSafeMeasurementLog populated with the entries from the file.
func LoadThreadSafeMeasurementLog(path string) (*ThreadSafeMeasurementLog, error) {
	if path == "" {
		return nil, NewContainerError("", "", "load", ErrInvalidSpec)
	}

	jsonData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrContainerNotFound
		}
		return nil, NewContainerError("", "", "load_read", err)
	}

	var data threadSafeMeasurementLogPersisted
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, NewContainerError("", "", "load_unmarshal", err)
	}

	log := &ThreadSafeMeasurementLog{
		entries: data.Entries,
		version: data.Version,
	}

	if log.version == 0 {
		log.version = 1
	}

	return log, nil
}

// extendHash computes the PCR extend operation: SHA256(current || extend)
func extendHash(current, extend []byte) []byte {
	h := sha256.New()
	h.Write(current)
	h.Write(extend)
	return h.Sum(nil)
}

// ComputeEntryHash computes the cumulative hash for a measurement entry.
// This is the hash that gets extended to the WorkloadPCR.
// The hash is computed as: SHA256(containerID || imageDigest || configDigest || eventType)
func ComputeEntryHash(containerID string, imageDigest, configDigest []byte, eventType MeasurementEventType) []byte {
	h := sha256.New()
	h.Write([]byte(containerID))
	if len(imageDigest) > 0 {
		h.Write(imageDigest)
	}
	if len(configDigest) > 0 {
		h.Write(configDigest)
	}
	h.Write([]byte(eventType))
	return h.Sum(nil)
}

// NewMeasurementEntry creates a new measurement entry with the computed
// cumulative hash.
func NewMeasurementEntry(
	containerID string,
	containerName string,
	eventType MeasurementEventType,
	imageDigest, configDigest []byte,
	description string,
) *MeasurementEntry {
	cumulativeHash := ComputeEntryHash(containerID, imageDigest, configDigest, eventType)

	return &MeasurementEntry{
		ContainerID:    containerID,
		ContainerName:  containerName,
		Timestamp:      time.Now(),
		EventType:      eventType,
		ImageDigest:    imageDigest,
		ConfigDigest:   configDigest,
		CumulativeHash: cumulativeHash,
		Description:    description,
	}
}

// ComputeExpectedPCRFromLog computes the expected PCR value from a measurement log.
// This is a convenience function for verification without an attestor instance.
func ComputeExpectedPCRFromLog(log *MeasurementLog) []byte {
	if log == nil || len(log.Entries) == 0 {
		return make([]byte, SHA256Size)
	}

	pcr := make([]byte, SHA256Size)
	for _, entry := range log.Entries {
		pcr = extendHash(pcr, entry.CumulativeHash)
	}
	return pcr
}
