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
	GatewayID  string      `json:"gateway_id"`
	Hostname   string      `json:"hostname,omitempty"`
	Mode       string      `json:"mode,omitempty"`
	ReportedAt time.Time   `json:"reported_at"`
	ReceivedAt time.Time   `json:"received_at"`
	Health     HealthState `json:"health"`
	BGP        BGPState    `json:"bgp"`
	IPAM       IPAMState   `json:"ipam"`
	PXE        PXEState    `json:"pxe"`
	DHCP       DHCPState   `json:"dhcp"`
	// DesiredConfig reports the last desired-config reconciliation (#555).
	DesiredConfig DesiredConfigState `json:"desired_config"`
	// Services reports one entry per configured service section: whether it
	// is running, whether the service itself calls itself healthy, and the
	// blocker when the gateway refuses to run it (#568).
	Services []ServiceState `json:"services,omitempty"`
	// Tunnels, Uplinks, HostFirewall, Firewall, NAT and Pipeline report what
	// the datapath services programmed. Each section is derived from the
	// service's own status; a service that is not running contributes
	// nothing rather than a zero value that reads as "installed and empty".
	Tunnels      []TunnelState      `json:"tunnels,omitempty"`
	Uplinks      []UplinkState      `json:"uplinks,omitempty"`
	HostFirewall *HostFirewallState `json:"host_firewall,omitempty"`
	Firewall     *FirewallState     `json:"firewall,omitempty"`
	NAT          *NATState          `json:"nat,omitempty"`
	Pipeline     *PipelineState     `json:"pipeline,omitempty"`
	Overlay      *OverlayState      `json:"overlay,omitempty"`
	Interfaces   []Interface        `json:"interfaces,omitempty"`
	Annotations  map[string]string  `json:"annotations,omitempty"`
}

// OverlayState reports the gatewayd overlay datapath and admission state.
type OverlayState struct {
	Running                  bool                  `json:"running"`
	LocalVTEP                string                `json:"local_vtep,omitempty"`
	VNICount                 int                   `json:"vni_count,omitempty"`
	RemoteVTEPCount          int                   `json:"remote_vtep_count,omitempty"`
	LocalMACCount            int                   `json:"local_mac_count,omitempty"`
	RemoteMACCount           int                   `json:"remote_mac_count,omitempty"`
	PrefixCount              int                   `json:"prefix_count,omitempty"`
	RefusedBindings          uint64                `json:"refused_bindings,omitempty"`
	RefusedReplays           uint64                `json:"refused_replays,omitempty"`
	L3VNI                    uint32                `json:"l3_vni,omitempty"`
	ARPSuppressionEnabled    bool                  `json:"arp_suppression_enabled,omitempty"`
	AnycastGatewayConfigured bool                  `json:"anycast_gateway_configured,omitempty"`
	StartedAt                time.Time             `json:"started_at,omitempty"`
	Uptime                   time.Duration         `json:"uptime,omitempty"`
	AdmittedVTEPs            []AdmittedVTEPState   `json:"admitted_vteps,omitempty"`
	NDCounters               OverlayNDCounterState `json:"nd_counters"`
}

// AdmittedVTEPState is a VTEP the overlay decap table currently admits.
type AdmittedVTEPState struct {
	VTEP           string    `json:"vtep"`
	DeviceID       uint64    `json:"device_id,omitempty"`
	HostID         string    `json:"host_id,omitempty"`
	Serial         string    `json:"serial,omitempty"`
	Hostname       string    `json:"hostname,omitempty"`
	AllocationID   string    `json:"allocation_id,omitempty"`
	BaselineSource string    `json:"baseline_source,omitempty"`
	ProfileID      uint64    `json:"profile_id,omitempty"`
	VerdictAt      time.Time `json:"verdict_at,omitempty"`
}

// OverlayNDCounterState reports overlay neighbour-discovery datapath counters.
type OverlayNDCounterState struct {
	Punted       uint64 `json:"punted"`
	Answered     uint64 `json:"answered"`
	MeterDropped uint64 `json:"meter_dropped"`
	QueueDropped uint64 `json:"queue_dropped"`
	FellThrough  uint64 `json:"fell_through"`
}

// ServiceState is one configured service section's disposition.
type ServiceState struct {
	// Name is the service section name (firewall, nat, tunnels, ...).
	Name string `json:"name"`
	// Active reports whether the service is started and its backend says
	// it is running.
	Active bool `json:"active"`
	// Healthy is the service's own health verdict.
	Healthy bool `json:"healthy"`
	// RefusedReason names the blocker for a section the gateway cannot run;
	// empty for a service that has a builder.
	RefusedReason string `json:"refused_reason,omitempty"`
}

// TunnelState is one managed tunnel as the tunnel manager reports it.
type TunnelState struct {
	Name      string `json:"name"`
	Transport string `json:"transport,omitempty"`
	Type      string `json:"type,omitempty"`
	// State is the link's operational state: up, down or unknown.
	State string `json:"state"`
	// Uplink names the uplink whose routing table carries the outer
	// packets; Bound reports whether that pin is installed.
	Uplink    string `json:"uplink,omitempty"`
	Bound     bool   `json:"bound,omitempty"`
	LocalIP   string `json:"local_ip,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	TunnelIP  string `json:"tunnel_ip,omitempty"`
	RxBytes   uint64 `json:"rx_bytes,omitempty"`
	TxBytes   uint64 `json:"tx_bytes,omitempty"`
	RxPackets uint64 `json:"rx_packets,omitempty"`
	TxPackets uint64 `json:"tx_packets,omitempty"`
	// RekeySeconds is the key rotation interval in seconds; zero for a
	// transport that carries no key material. LastRekey is when the last
	// rotation succeeded.
	RekeySeconds int64     `json:"rekey_seconds,omitempty"`
	LastRekey    time.Time `json:"last_rekey,omitempty"`
}

// UplinkState is one WAN uplink's policy-routing state (#582): the table it
// owns, the next hops in it, and the tunnels pinned to it.
type UplinkState struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface,omitempty"`
	Table     int      `json:"table"`
	GatewayV4 string   `json:"gateway_v4,omitempty"`
	GatewayV6 string   `json:"gateway_v6,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Priority  int      `json:"priority,omitempty"`
	RuleCount int      `json:"rule_count"`
	Tunnels   []string `json:"tunnels,omitempty"`
}

// HostFirewallState is the nftables host filter's state (#569).
type HostFirewallState struct {
	Active bool `json:"active"`
	// Installed reports whether the table was present at the last check.
	Installed bool `json:"installed"`
	// Fingerprint identifies the ruleset last applied successfully.
	Fingerprint   string    `json:"fingerprint,omitempty"`
	RuleCount     int       `json:"rule_count"`
	LastReconcile time.Time `json:"last_reconcile,omitempty"`
	// LastError is the last reconcile failure, empty when the last one
	// succeeded.
	LastError string `json:"last_error,omitempty"`
}

// FirewallState is the OVS conntrack firewall's state.
type FirewallState struct {
	Active        bool              `json:"active"`
	FlowCount     int               `json:"flow_count"`
	LastReconcile time.Time         `json:"last_reconcile,omitempty"`
	CTZones       map[string]uint16 `json:"ct_zones,omitempty"`
}

// NATState is the OVS NAT service's state, including the per-uplink SNAT
// pools of a dual-uplink deployment (#586).
type NATState struct {
	Active      bool             `json:"active"`
	SNATEnabled bool             `json:"snat_enabled"`
	DNATRules   int              `json:"dnat_rules"`
	CTZone      uint16           `json:"ct_zone,omitempty"`
	Uplinks     []NATUplinkState `json:"uplinks,omitempty"`
}

// NATUplinkState describes one uplink's translation resources. The counts
// describe configured capacity: the OVS datapath exposes no per-range
// allocation counter, so utilisation is not observable here.
type NATUplinkState struct {
	Name          string `json:"name"`
	Default       bool   `json:"default,omitempty"`
	PoolAddresses int    `json:"pool_addresses"`
	Ports         int    `json:"ports"`
	Static        int    `json:"static"`
}

// PipelineState is the base OVS pipeline the gateway holds on its bridge
// (#567): who owns it, where table 30 terminates, and the fail mode held
// while it is installed.
type PipelineState struct {
	Installed bool   `json:"installed"`
	Bridge    string `json:"bridge,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Terminal  string `json:"terminal,omitempty"`
	FailMode  string `json:"fail_mode,omitempty"`
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
	// Peers is one entry per configured neighbour, sorted by address.
	Peers []BGPPeerState `json:"peers,omitempty"`
}

// BGPPeerState is one neighbour's session as the speaker reports it.
type BGPPeerState struct {
	Address     string `json:"address"`
	ASN         uint32 `json:"asn,omitempty"`
	Description string `json:"description,omitempty"`
	// State is the RFC 4271 FSM state: idle, connect, active, opensent,
	// openconfirm or established.
	State string `json:"state"`
	// UptimeSeconds is how long the session has been established.
	UptimeSeconds    int64 `json:"uptime_seconds,omitempty"`
	AdminDown        bool  `json:"admin_down,omitempty"`
	PrefixesReceived int64 `json:"prefixes_received"`
	// PrefixesAccepted is what import policy admitted; the gap to
	// PrefixesReceived is what max-prefix and the prefix lists rejected.
	PrefixesAccepted int64  `json:"prefixes_accepted"`
	PrefixesSent     int64  `json:"prefixes_sent"`
	MessagesReceived int64  `json:"messages_received,omitempty"`
	MessagesSent     int64  `json:"messages_sent,omitempty"`
	LocalAddress     string `json:"local_address,omitempty"`
	RemoteRouterID   string `json:"remote_router_id,omitempty"`
	// HoldTimeSeconds is the negotiated hold timer.
	HoldTimeSeconds int `json:"hold_time_seconds,omitempty"`
	// Families are the address families enabled on the session.
	Families []string `json:"families,omitempty"`
	// LastError is the last session error the speaker recorded.
	LastError string `json:"last_error,omitempty"`
	// BFD is the neighbour's single-hop BFD session (RFC 5881), absent when
	// BFD is not configured toward it.
	BFD *BFDState `json:"bfd,omitempty"`
}

// BFDState is one BGP neighbour's BFD session.
type BFDState struct {
	// State and RemoteState are up, down, admin-down, init or unknown.
	State       string `json:"state"`
	RemoteState string `json:"remote_state,omitempty"`
	// FailureTransitions counts session failures since it was created;
	// LastFailure is when the last one happened.
	FailureTransitions uint64    `json:"failure_transitions,omitempty"`
	LastFailure        time.Time `json:"last_failure,omitempty"`
	// Diagnostic and RemoteDiagnostic are the RFC 5880 §4.1 codes behind
	// the last state change at each end.
	Diagnostic       string `json:"diagnostic,omitempty"`
	RemoteDiagnostic string `json:"remote_diagnostic,omitempty"`
	// TxIntervalMS and RxIntervalMS are the configured timers in
	// milliseconds; DetectionMultiplier the configured multiplier.
	TxIntervalMS        int64 `json:"tx_interval_ms,omitempty"`
	RxIntervalMS        int64 `json:"rx_interval_ms,omitempty"`
	DetectionMultiplier uint8 `json:"detection_multiplier,omitempty"`
}

// IPAMState reports pool consumption.
type IPAMState struct {
	Pools []IPAMPoolStats `json:"pools,omitempty"`
}

// IPAMPoolStats is per-pool occupancy.
type IPAMPoolStats struct {
	Name           string  `json:"name"`
	CIDR           string  `json:"cidr,omitempty"`
	Allocated      uint64  `json:"allocated"`
	Available      uint64  `json:"available"`
	Total          uint64  `json:"total"`
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
	Status       string `json:"status"`
	LeaseCount   uint64 `json:"lease_count"`
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
		return nil, &WrappedError{Msg: fmt.Sprintf("gateway/state: mkdir %s", root), Err: err}
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
		return nil, &WrappedError{Msg: fmt.Sprintf("gateway/state: decode %s", gatewayID), Err: err}
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
