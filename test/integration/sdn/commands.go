//go:build integration

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

package sdn

import (
	"context"
	"time"
)

// SDNCommands defines the central command set for SDN integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type SDNCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Bridge Commands (platformctl sdn bridge ...)
	BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error)
	BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error)
	BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error)
	BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error)

	// Port Commands (platformctl sdn port ...)
	PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error)
	PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error)
	PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error)
	PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error)
	PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error)

	// Flow Commands (platformctl sdn flow ...)
	FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error)
	FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error)
	FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error)

	// VLAN Commands (platformctl sdn vlan ...)
	VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error)
	VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error)
	VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error)

	// Policy Commands (platformctl sdn policy ...)
	PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error)
	PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error)
	PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error)
}

// =============================================================================
// Bridge Options and Results
// =============================================================================

// BridgeCreateOptions contains options for creating a new bridge.
type BridgeCreateOptions struct {
	BridgeID    string
	Name        string
	Description string
	Type        string // "ovs", "linux", "dpdk"
	DatapathID  string
	FailMode    string // "secure", "standalone"
	STP         bool
	RSTP        bool
	MTU         int32
	Tags        map[string]string
}

// BridgeCreateResult contains the result of a bridge creation operation.
type BridgeCreateResult struct {
	BridgeID    string
	Name        string
	Type        string
	DatapathID  string
	Status      string
	CreatedAt   time.Time
	PortCount   int32
	Description string
}

// BridgeGetResult contains the result of a bridge retrieval operation.
type BridgeGetResult struct {
	BridgeID    string
	Name        string
	Type        string
	DatapathID  string
	Status      string
	FailMode    string
	STP         bool
	RSTP        bool
	MTU         int32
	PortCount   int32
	FlowCount   int32
	Description string
	Tags        map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Ports       []PortSummary
}

// BridgeDeleteOptions contains options for deleting a bridge.
type BridgeDeleteOptions struct {
	Force          bool
	DeletePorts    bool
	DeleteFlows    bool
	CleanupTimeout int32
}

// BridgeDeleteResult contains the result of a bridge deletion operation.
type BridgeDeleteResult struct {
	BridgeID   string
	Deleted    bool
	PortsClean int32
	FlowsClean int32
}

// BridgeListOptions contains options for listing bridges.
type BridgeListOptions struct {
	Type   string
	Status string
	Limit  int32
	Cursor string
}

// BridgeListResult contains the result of a bridge list operation.
type BridgeListResult struct {
	Bridges    []BridgeSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// BridgeSummary contains summary information about a bridge.
type BridgeSummary struct {
	BridgeID   string
	Name       string
	Type       string
	Status     string
	PortCount  int32
	FlowCount  int32
	DatapathID string
	CreatedAt  time.Time
}

// =============================================================================
// Port Options and Results
// =============================================================================

// PortAddOptions contains options for adding a port to a bridge.
type PortAddOptions struct {
	BridgeID     string
	PortID       string
	Name         string
	Type         string // "internal", "system", "vxlan", "gre", "geneve", "patch"
	Tag          int32  // VLAN tag for access ports
	Trunks       []int32
	Interface    string
	MAC          string
	MTU          int32
	AdminState   string // "up", "down"
	PeerPort     string // For patch ports
	RemoteIP     string // For tunnel ports
	LocalIP      string // For tunnel ports
	VNI          int32  // For VXLAN/Geneve
	Key          string // For GRE
	Options      map[string]string
	IngressRate  uint64 // Rate limit in bps
	EgressRate   uint64 // Rate limit in bps
	IngressBurst uint64 // Burst size in bytes
	EgressBurst  uint64 // Burst size in bytes
}

// PortAddResult contains the result of a port add operation.
type PortAddResult struct {
	BridgeID   string
	PortID     string
	PortNumber int32
	Name       string
	Type       string
	MAC        string
	Status     string
	CreatedAt  time.Time
}

// PortDeleteResult contains the result of a port deletion operation.
type PortDeleteResult struct {
	BridgeID string
	PortID   string
	Deleted  bool
}

// PortSetStateOptions contains options for setting port state.
type PortSetStateOptions struct {
	AdminState   string // "up", "down"
	IngressRate  uint64 // Ingress policing rate in bps (0 leaves it unchanged)
	EgressRate   uint64 // Egress shaping rate in bps (0 leaves it unchanged)
	IngressBurst uint64 // Ingress policing burst in bits
	EgressBurst  uint64 // Egress shaping burst in bits
}

// PortStateResult contains the result of a port state operation.
type PortStateResult struct {
	BridgeID     string
	PortID       string
	PortNumber   int32
	AdminState   string
	OperState    string
	LinkState    string
	Speed        uint64
	Duplex       string
	IngressRate  uint64
	EgressRate   uint64
	IngressBurst uint64
	EgressBurst  uint64
	UpdatedAt    time.Time
}

// PortStatsResult contains port statistics.
type PortStatsResult struct {
	BridgeID     string
	PortID       string
	PortNumber   int32
	RxPackets    uint64
	TxPackets    uint64
	RxBytes      uint64
	TxBytes      uint64
	RxDropped    uint64
	TxDropped    uint64
	RxErrors     uint64
	TxErrors     uint64
	RxFrameErr   uint64
	RxOverErr    uint64
	RxCRCErr     uint64
	Collisions   uint64
	Duration     int64
	DurationNsec int64
	RetrievedAt  time.Time
}

// PortSummary contains summary information about a port.
type PortSummary struct {
	PortID     string
	PortNumber int32
	Name       string
	Type       string
	AdminState string
	OperState  string
	MAC        string
	Tag        int32
}

// =============================================================================
// Flow Options and Results
// =============================================================================

// FlowAddOptions contains options for adding a flow.
type FlowAddOptions struct {
	BridgeID    string
	FlowID      string
	Table       int32
	Priority    int32
	Match       FlowMatch
	Actions     []FlowAction
	IdleTimeout int32
	HardTimeout int32
	Cookie      uint64
	Flags       []string
}

// FlowMatch defines flow matching criteria.
type FlowMatch struct {
	InPort    int32
	DlSrc     string // Source MAC
	DlDst     string // Destination MAC
	DlType    int32  // Ethertype
	DlVLAN    int32  // VLAN ID
	DlVLANPCP int32  // VLAN priority
	NwSrc     string // Source IP
	NwDst     string // Destination IP
	NwProto   int32  // IP protocol
	NwTOS     int32  // IP TOS
	TpSrc     int32  // Source port (TCP/UDP)
	TpDst     int32  // Destination port (TCP/UDP)
	ICMPType  int32
	ICMPCode  int32
	ARPOp     int32
	ARPSha    string // ARP source hardware address
	ARPTha    string // ARP target hardware address
	ARPSpa    string // ARP source protocol address
	ARPTpa    string // ARP target protocol address
	Metadata  uint64
	TunnelID  uint64
	TunnelSrc string
	TunnelDst string
}

// FlowAction defines a flow action.
type FlowAction struct {
	Type    string // "output", "drop", "normal", "flood", "controller", "push_vlan", "pop_vlan", "set_field", "group", "goto_table"
	Port    int32
	VLANID  int32
	Field   string
	Value   string
	GroupID int32
	TableID int32
}

// FlowAddResult contains the result of a flow add operation.
type FlowAddResult struct {
	BridgeID  string
	FlowID    string
	Table     int32
	Priority  int32
	Cookie    uint64
	CreatedAt time.Time
}

// FlowDeleteResult contains the result of a flow deletion operation.
type FlowDeleteResult struct {
	BridgeID string
	FlowID   string
	Deleted  bool
}

// FlowListOptions contains options for listing flows.
type FlowListOptions struct {
	Table  int32
	Cookie uint64
	Match  *FlowMatch
	Limit  int32
	Cursor string
}

// FlowListResult contains the result of a flow list operation.
type FlowListResult struct {
	BridgeID   string
	Flows      []FlowSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// FlowSummary contains summary information about a flow.
type FlowSummary struct {
	FlowID      string
	Table       int32
	Priority    int32
	Cookie      uint64
	PacketCount uint64
	ByteCount   uint64
	Duration    int64
	IdleAge     int64
	HardAge     int64
	Match       FlowMatch
	Actions     []FlowAction
}

// =============================================================================
// VLAN Options and Results
// =============================================================================

// VLANCreateOptions contains options for creating a VLAN.
type VLANCreateOptions struct {
	VLANID      int32
	Name        string
	Description string
	BridgeIDs   []string // Bridges to add this VLAN to
	Tagged      []string // Port IDs for tagged membership
	Untagged    []string // Port IDs for untagged membership
}

// VLANCreateResult contains the result of a VLAN creation operation.
type VLANCreateResult struct {
	VLANID      int32
	Name        string
	Description string
	Status      string
	BridgeCount int32
	PortCount   int32
	CreatedAt   time.Time
}

// VLANDeleteResult contains the result of a VLAN deletion operation.
type VLANDeleteResult struct {
	VLANID  int32
	Deleted bool
}

// VLANListOptions contains options for listing VLANs.
type VLANListOptions struct {
	BridgeID string
	Limit    int32
	Cursor   string
}

// VLANListResult contains the result of a VLAN list operation.
type VLANListResult struct {
	VLANs      []VLANSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// VLANSummary contains summary information about a VLAN.
type VLANSummary struct {
	VLANID      int32
	Name        string
	Description string
	Status      string
	BridgeCount int32
	PortCount   int32
	CreatedAt   time.Time
}

// =============================================================================
// Policy Options and Results
// =============================================================================

// PolicyApplyOptions contains options for applying a network policy.
type PolicyApplyOptions struct {
	PolicyID    string
	Name        string
	Description string
	Type        string // "acl", "qos", "nat", "firewall", "routing"
	BridgeID    string // Bridge to apply the policy to
	Priority    int32
	Enabled     bool
	Rules       []PolicyRule
	Targets     []PolicyTarget
	Schedule    *PolicySchedule
}

// PolicyRule defines a policy rule.
type PolicyRule struct {
	RuleID      string
	Priority    int32
	Match       PolicyMatch
	Action      string // "allow", "deny", "rate-limit", "redirect", "mirror", "log"
	ActionValue string
	Log         bool
	Counter     bool
}

// PolicyMatch defines policy matching criteria.
type PolicyMatch struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      int32
	DestinationPort int32
	Protocol        string
	Direction       string // "ingress", "egress", "both"
	Interface       string
	VLANID          int32
	DSCP            int32
	Application     string
}

// PolicyTarget defines where a policy applies.
type PolicyTarget struct {
	Type      string // "bridge", "port", "vlan", "interface"
	ID        string
	Direction string
}

// PolicySchedule defines when a policy is active.
type PolicySchedule struct {
	StartTime string // HH:MM format
	EndTime   string
	Days      []string // "monday", "tuesday", etc.
	Timezone  string
	Enabled   bool
}

// PolicyApplyResult contains the result of a policy apply operation.
type PolicyApplyResult struct {
	PolicyID    string
	Name        string
	Type        string
	Status      string
	RuleCount   int32
	TargetCount int32
	AppliedAt   time.Time
}

// PolicyGetResult contains the result of a policy retrieval operation.
type PolicyGetResult struct {
	PolicyID    string
	Name        string
	Description string
	Type        string
	Priority    int32
	Enabled     bool
	Status      string
	Rules       []PolicyRule
	Targets     []PolicyTarget
	Schedule    *PolicySchedule
	HitCount    uint64
	ByteCount   uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PolicyListOptions contains options for listing policies.
type PolicyListOptions struct {
	Type     string
	Enabled  *bool
	TargetID string
	Limit    int32
	Cursor   string
}

// PolicyListResult contains the result of a policy list operation.
type PolicyListResult struct {
	Policies   []PolicySummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// PolicySummary contains summary information about a policy.
type PolicySummary struct {
	PolicyID    string
	Name        string
	Type        string
	Priority    int32
	Enabled     bool
	Status      string
	RuleCount   int32
	TargetCount int32
	HitCount    uint64
	CreatedAt   time.Time
}
