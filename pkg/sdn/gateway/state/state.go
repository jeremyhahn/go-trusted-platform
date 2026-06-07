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

// Package state persists the latest telemetry snapshot from each
// gatewayd that has reported to the CP. The CP webserver reads from
// this store to back GET /api/v1/gateway/state and to populate the
// WebUI's Gateway page; gatewayd writes via POST
// /api/v1/gateway/telemetry on a periodic tick.
//
// Phase 2.3 first-ship is single-node file-backed
// (<PlatformDir>/gateway/state/<gateway_id>.json). When the cluster
// needs cross-CP state sharing, swap the Store implementation for a
// QuicBaaS-backed one — the interface stays stable.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Snapshot is the per-gatewayd telemetry payload the CP caches. It
// is intentionally a flat structure so the WebUI's Gateway page can
// render it without re-parsing nested control structures.
type Snapshot struct {
	GatewayID    string         `json:"gateway_id"`
	Hostname     string         `json:"hostname,omitempty"`
	Mode         string         `json:"mode,omitempty"`
	ReportedAt   time.Time      `json:"reported_at"`
	ReceivedAt   time.Time      `json:"received_at"`
	Health       HealthState    `json:"health"`
	BGP          BGPState       `json:"bgp"`
	IPAM         IPAMState      `json:"ipam"`
	PXE          PXEState       `json:"pxe"`
	DHCP         DHCPState      `json:"dhcp"`
	Interfaces   []Interface    `json:"interfaces,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// HealthState carries the overall liveness summary. Components is
// granular so the WebUI can render per-subsystem badges (BGP up,
// PXE down, etc.).
type HealthState struct {
	Status     string            `json:"status"` // "healthy" | "degraded" | "unhealthy"
	Components map[string]string `json:"components,omitempty"`
	Message    string            `json:"message,omitempty"`
}

// BGPState is the BGP control-plane snapshot.
type BGPState struct {
	LocalASN          uint32   `json:"local_asn,omitempty"`
	RouterID          string   `json:"router_id,omitempty"`
	PeerCount         int      `json:"peer_count"`
	EstablishedPeers  int      `json:"established_peers"`
	AnnouncedPrefixes []string `json:"announced_prefixes,omitempty"`
	ReceivedPrefixes  int      `json:"received_prefixes"`
}

// IPAMState reports pool consumption.
type IPAMState struct {
	Pools []IPAMPoolStats `json:"pools,omitempty"`
}

// IPAMPoolStats is per-pool occupancy.
type IPAMPoolStats struct {
	Name        string `json:"name"`
	CIDR        string `json:"cidr,omitempty"`
	Allocated   uint64 `json:"allocated"`
	Available   uint64 `json:"available"`
	Total       uint64 `json:"total"`
	UtilizationPct float64 `json:"utilization_pct"`
}

// PXEState reports whether the gateway's PXE server is up + the
// number of installs it has served.
type PXEState struct {
	Status        string    `json:"status"` // "running" | "stopped" | "degraded"
	ListenAddress string    `json:"listen_address,omitempty"`
	BootsServed   uint64    `json:"boots_served"`
	StartedAt     time.Time `json:"started_at,omitempty"`
}

// DHCPState reports lease counts.
type DHCPState struct {
	Status      string `json:"status"`
	LeaseCount  uint64 `json:"lease_count"`
	ExpiringSoon uint64 `json:"expiring_soon"`
}

// Interface is a per-link snapshot. Used for the WebUI's NIC table.
type Interface struct {
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	MAC       string         `json:"mac,omitempty"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	RXBytes   uint64         `json:"rx_bytes,omitempty"`
	TXBytes   uint64         `json:"tx_bytes,omitempty"`
}

// Store persists Snapshots keyed by gateway ID.
type Store interface {
	Put(snap *Snapshot) error
	Get(gatewayID string) (*Snapshot, error)
	List() ([]*Snapshot, error)
	Delete(gatewayID string) error
}

// FileStore is the default Store implementation. One JSON file per
// gateway under <root>/<gateway_id>.json, atomic temp+rename.
type FileStore struct {
	root string
	mu   sync.Mutex
}

// NewFileStore prepares root and returns a ready store.
func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, errInvalidStateConfig{Field: "root", Reason: "cannot be empty"}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("gateway/state: mkdir %s: %w", root, err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) path(id string) string {
	return filepath.Join(s.root, sanitizeID(id)+".json")
}

// Put writes the snapshot atomically. ReceivedAt is stamped server-
// side so a misbehaving gatewayd can't pre-date its report.
func (s *FileStore) Put(snap *Snapshot) error {
	if snap == nil {
		return errInvalidStateConfig{Field: "snapshot", Reason: "nil"}
	}
	if snap.GatewayID == "" {
		return errInvalidStateConfig{Field: "snapshot.gateway_id", Reason: "empty"}
	}
	snap.ReceivedAt = time.Now().UTC()
	if snap.ReportedAt.IsZero() {
		snap.ReportedAt = snap.ReceivedAt
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	path := s.path(snap.GatewayID)
	tmp := path + ".tmp"
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Get loads a snapshot by gateway ID. Missing returns
// ErrSnapshotNotFound so callers can distinguish "no gatewayd has
// reported" from a real IO error.
func (s *FileStore) Get(gatewayID string) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path(gatewayID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSnapshotNotFound{GatewayID: gatewayID}
		}
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("gateway/state: decode %s: %w", gatewayID, err)
	}
	return &snap, nil
}

// List walks all snapshots, newest ReportedAt first.
func (s *FileStore) List() ([]*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]*Snapshot, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, e.Name()))
		if err != nil {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		out = append(out, &snap)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ReportedAt.After(out[j].ReportedAt)
	})
	return out, nil
}

// Delete removes a snapshot.
func (s *FileStore) Delete(gatewayID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path(gatewayID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrSnapshotNotFound{GatewayID: gatewayID}
		}
		return err
	}
	return nil
}

// sanitizeID strips path separators from a gateway ID so a malicious
// caller can't write outside the store root.
func sanitizeID(id string) string {
	out := strings.ReplaceAll(id, "/", "_")
	out = strings.ReplaceAll(out, "\\", "_")
	out = strings.ReplaceAll(out, "..", "_")
	if out == "" {
		out = "default"
	}
	return out
}

// ErrSnapshotNotFound is returned when Get/Delete is called for a
// gateway ID that has never reported.
type ErrSnapshotNotFound struct {
	GatewayID string
}

func (e ErrSnapshotNotFound) Error() string {
	return "gateway/state: snapshot not found for " + e.GatewayID
}

type errInvalidStateConfig struct {
	Field  string
	Reason string
}

func (e errInvalidStateConfig) Error() string {
	return fmt.Sprintf("gateway/state: invalid %s: %s", e.Field, e.Reason)
}
