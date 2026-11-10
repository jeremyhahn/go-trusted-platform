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

package cluster

import (
	"sync"
	"testing"
	"time"
)

func TestNodeState_String(t *testing.T) {
	tests := []struct {
		state NodeState
		want  string
	}{
		{NodeStateUnknown, "unknown"},
		{NodeStateHealthy, "healthy"},
		{NodeStateUnhealthy, "unhealthy"},
		{NodeStateSuspect, "suspect"},
		{NodeStateLeaving, "leaving"},
		{NodeState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("NodeState.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNode_IsHealthy(t *testing.T) {
	tests := []struct {
		name  string
		state NodeState
		want  bool
	}{
		{"healthy node", NodeStateHealthy, true},
		{"unhealthy node", NodeStateUnhealthy, false},
		{"unknown node", NodeStateUnknown, false},
		{"suspect node", NodeStateSuspect, false},
		{"leaving node", NodeStateLeaving, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{State: tt.state}
			if got := node.IsHealthy(); got != tt.want {
				t.Errorf("Node.IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNode_Clone(t *testing.T) {
	t.Run("clones all fields", func(t *testing.T) {
		now := time.Now()
		original := &Node{
			ID:          42,
			Address:     "192.168.1.10:8080",
			RaftAddress: "192.168.1.10:9000",
			IsLeader:    true,
			State:       NodeStateHealthy,
			LastSeen:    now,
			JoinTime:    now.Add(-1 * time.Hour),
			Metadata: map[string]string{
				"region": "us-west-1",
				"zone":   "a",
			},
		}

		clone := original.Clone()

		if clone == original {
			t.Error("clone should be a different pointer")
		}

		if clone.ID != original.ID {
			t.Errorf("ID = %d, want %d", clone.ID, original.ID)
		}
		if clone.Address != original.Address {
			t.Errorf("Address = %s, want %s", clone.Address, original.Address)
		}
		if clone.RaftAddress != original.RaftAddress {
			t.Errorf("RaftAddress = %s, want %s", clone.RaftAddress, original.RaftAddress)
		}
		if clone.IsLeader != original.IsLeader {
			t.Errorf("IsLeader = %v, want %v", clone.IsLeader, original.IsLeader)
		}
		if clone.State != original.State {
			t.Errorf("State = %v, want %v", clone.State, original.State)
		}
		if !clone.LastSeen.Equal(original.LastSeen) {
			t.Errorf("LastSeen = %v, want %v", clone.LastSeen, original.LastSeen)
		}
		if !clone.JoinTime.Equal(original.JoinTime) {
			t.Errorf("JoinTime = %v, want %v", clone.JoinTime, original.JoinTime)
		}
	})

	t.Run("deep copies metadata", func(t *testing.T) {
		original := &Node{
			ID:       1,
			Metadata: map[string]string{"key": "value"},
		}

		clone := original.Clone()

		// Modify original
		original.Metadata["key"] = "modified"
		original.Metadata["new"] = "value"

		// Clone should not be affected
		if clone.Metadata["key"] != "value" {
			t.Error("modifying original metadata affected clone")
		}
		if _, exists := clone.Metadata["new"]; exists {
			t.Error("adding to original metadata affected clone")
		}
	})

	t.Run("handles nil metadata", func(t *testing.T) {
		original := &Node{
			ID:       1,
			Metadata: nil,
		}

		clone := original.Clone()

		if clone.Metadata != nil {
			t.Errorf("expected nil Metadata, got %v", clone.Metadata)
		}
	})

	t.Run("handles nil node", func(t *testing.T) {
		var node *Node
		clone := node.Clone()

		if clone != nil {
			t.Errorf("expected nil, got %v", clone)
		}
	})
}

func TestNodeList_Count(t *testing.T) {
	tests := []struct {
		name  string
		nodes []*Node
		want  int
	}{
		{"empty list", nil, 0},
		{"one node", []*Node{{ID: 1}}, 1},
		{"three nodes", []*Node{{ID: 1}, {ID: 2}, {ID: 3}}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nl := &NodeList{Nodes: tt.nodes}
			if got := nl.Count(); got != tt.want {
				t.Errorf("NodeList.Count() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNodeList_HealthyCount(t *testing.T) {
	tests := []struct {
		name  string
		nodes []*Node
		want  int
	}{
		{"empty list", nil, 0},
		{
			"all healthy",
			[]*Node{
				{ID: 1, State: NodeStateHealthy},
				{ID: 2, State: NodeStateHealthy},
			},
			2,
		},
		{
			"mixed states",
			[]*Node{
				{ID: 1, State: NodeStateHealthy},
				{ID: 2, State: NodeStateUnhealthy},
				{ID: 3, State: NodeStateHealthy},
				{ID: 4, State: NodeStateSuspect},
			},
			2,
		},
		{
			"none healthy",
			[]*Node{
				{ID: 1, State: NodeStateUnhealthy},
				{ID: 2, State: NodeStateUnknown},
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nl := &NodeList{Nodes: tt.nodes}
			if got := nl.HealthyCount(); got != tt.want {
				t.Errorf("NodeList.HealthyCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNodeList_FindByID(t *testing.T) {
	nodes := []*Node{
		{ID: 1, Address: "addr1"},
		{ID: 2, Address: "addr2"},
		{ID: 3, Address: "addr3"},
	}

	nl := &NodeList{Nodes: nodes}

	t.Run("finds existing node", func(t *testing.T) {
		node := nl.FindByID(2)
		if node == nil {
			t.Fatal("expected to find node")
		}
		if node.Address != "addr2" {
			t.Errorf("Address = %s, want addr2", node.Address)
		}
	})

	t.Run("returns nil for non-existent node", func(t *testing.T) {
		node := nl.FindByID(99)
		if node != nil {
			t.Errorf("expected nil, got %v", node)
		}
	})

	t.Run("handles empty list", func(t *testing.T) {
		empty := &NodeList{}
		node := empty.FindByID(1)
		if node != nil {
			t.Errorf("expected nil, got %v", node)
		}
	})
}

func TestNodeList_Healthy(t *testing.T) {
	nodes := []*Node{
		{ID: 1, State: NodeStateHealthy},
		{ID: 2, State: NodeStateUnhealthy},
		{ID: 3, State: NodeStateHealthy},
		{ID: 4, State: NodeStateSuspect},
	}

	nl := &NodeList{Nodes: nodes}
	healthy := nl.Healthy()

	if len(healthy) != 2 {
		t.Errorf("len(Healthy()) = %d, want 2", len(healthy))
	}

	// Verify correct nodes are returned
	for _, n := range healthy {
		if n.State != NodeStateHealthy {
			t.Errorf("Healthy() returned node with state %v", n.State)
		}
	}
}

// Extended Node Tests

func TestExtendedNodeState_String(t *testing.T) {
	tests := []struct {
		state ExtendedNodeState
		want  string
	}{
		{ExtNodeStateUnknown, "unknown"},
		{ExtNodeStateHealthy, "healthy"},
		{ExtNodeStateUnhealthy, "unhealthy"},
		{ExtNodeStateUnreachable, "unreachable"},
		{ExtNodeStateLeaving, "leaving"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("ExtendedNodeState.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtendedNodeState_IsValid(t *testing.T) {
	tests := []struct {
		state ExtendedNodeState
		want  bool
	}{
		{ExtNodeStateUnknown, true},
		{ExtNodeStateHealthy, true},
		{ExtNodeStateUnhealthy, true},
		{ExtNodeStateUnreachable, true},
		{ExtNodeStateLeaving, true},
		{ExtendedNodeState("invalid"), false},
		{ExtendedNodeState(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsValid(); got != tt.want {
				t.Errorf("ExtendedNodeState(%q).IsValid() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestExtendedNodeState_ToNodeState(t *testing.T) {
	tests := []struct {
		state ExtendedNodeState
		want  NodeState
	}{
		{ExtNodeStateHealthy, NodeStateHealthy},
		{ExtNodeStateUnhealthy, NodeStateUnhealthy},
		{ExtNodeStateLeaving, NodeStateLeaving},
		{ExtNodeStateUnknown, NodeStateUnknown},
		{ExtNodeStateUnreachable, NodeStateUnknown},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.ToNodeState(); got != tt.want {
				t.Errorf("ExtendedNodeState(%q).ToNodeState() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestParseExtendedNodeState(t *testing.T) {
	tests := []struct {
		input   string
		want    ExtendedNodeState
		wantErr bool
	}{
		{"unknown", ExtNodeStateUnknown, false},
		{"healthy", ExtNodeStateHealthy, false},
		{"unhealthy", ExtNodeStateUnhealthy, false},
		{"unreachable", ExtNodeStateUnreachable, false},
		{"leaving", ExtNodeStateLeaving, false},
		{"invalid", ExtendedNodeState(""), true},
		{"", ExtendedNodeState(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseExtendedNodeState(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExtendedNodeState(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseExtendedNodeState(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAllExtendedNodeStates(t *testing.T) {
	states := AllExtendedNodeStates()

	if len(states) != 5 {
		t.Errorf("AllExtendedNodeStates() returned %d states, want 5", len(states))
	}

	for _, state := range states {
		if !state.IsValid() {
			t.Errorf("AllExtendedNodeStates() returned invalid state: %q", state)
		}
	}
}

func TestExtendedNode_Uptime(t *testing.T) {
	t.Run("returns duration since join time", func(t *testing.T) {
		node := &ExtendedNode{
			ID:       1,
			JoinTime: time.Now().Add(-1 * time.Hour),
		}

		uptime := node.Uptime()
		if uptime < 59*time.Minute || uptime > 61*time.Minute {
			t.Errorf("Uptime() = %v, expected approximately 1 hour", uptime)
		}
	})

	t.Run("returns zero for zero join time", func(t *testing.T) {
		node := &ExtendedNode{
			ID:       1,
			JoinTime: time.Time{},
		}

		uptime := node.Uptime()
		if uptime != 0 {
			t.Errorf("Uptime() = %v, want 0", uptime)
		}
	})
}

func TestExtendedNode_IsHealthy(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		state    ExtendedNodeState
		lastSeen time.Time
		want     bool
	}{
		{
			name:     "healthy with recent heartbeat",
			state:    ExtNodeStateHealthy,
			lastSeen: now.Add(-10 * time.Second),
			want:     true,
		},
		{
			name:     "healthy but stale heartbeat",
			state:    ExtNodeStateHealthy,
			lastSeen: now.Add(-1 * time.Minute),
			want:     false,
		},
		{
			name:     "unhealthy state",
			state:    ExtNodeStateUnhealthy,
			lastSeen: now,
			want:     false,
		},
		{
			name:     "unreachable state",
			state:    ExtNodeStateUnreachable,
			lastSeen: now,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &ExtendedNode{
				ID:       1,
				State:    tt.state,
				LastSeen: tt.lastSeen,
			}

			if got := node.IsHealthy(); got != tt.want {
				t.Errorf("ExtendedNode.IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedNode_Clone(t *testing.T) {
	t.Run("clones all fields", func(t *testing.T) {
		now := time.Now()
		original := &ExtendedNode{
			ID:          42,
			Address:     "192.168.1.10:8080",
			RaftAddress: "192.168.1.10:9000",
			State:       ExtNodeStateHealthy,
			IsLeader:    true,
			LastSeen:    now,
			JoinTime:    now.Add(-1 * time.Hour),
		}

		clone := original.Clone()

		if clone == original {
			t.Error("clone should be a different pointer")
		}

		if clone.ID != original.ID {
			t.Errorf("ID = %d, want %d", clone.ID, original.ID)
		}
		if clone.Address != original.Address {
			t.Errorf("Address = %s, want %s", clone.Address, original.Address)
		}
		if clone.RaftAddress != original.RaftAddress {
			t.Errorf("RaftAddress = %s, want %s", clone.RaftAddress, original.RaftAddress)
		}
		if clone.State != original.State {
			t.Errorf("State = %v, want %v", clone.State, original.State)
		}
		if clone.IsLeader != original.IsLeader {
			t.Errorf("IsLeader = %v, want %v", clone.IsLeader, original.IsLeader)
		}
	})

	t.Run("handles nil node", func(t *testing.T) {
		var node *ExtendedNode
		clone := node.Clone()

		if clone != nil {
			t.Errorf("expected nil, got %v", clone)
		}
	})
}

func TestExtendedNode_ToBaseNode(t *testing.T) {
	t.Run("converts to base node", func(t *testing.T) {
		now := time.Now()
		extended := &ExtendedNode{
			ID:          42,
			Address:     "192.168.1.10:8080",
			RaftAddress: "192.168.1.10:9000",
			State:       ExtNodeStateHealthy,
			IsLeader:    true,
			LastSeen:    now,
			JoinTime:    now.Add(-1 * time.Hour),
		}

		base := extended.ToBaseNode()

		if base.ID != extended.ID {
			t.Errorf("ID = %d, want %d", base.ID, extended.ID)
		}
		if base.Address != extended.Address {
			t.Errorf("Address = %s, want %s", base.Address, extended.Address)
		}
		if base.State != NodeStateHealthy {
			t.Errorf("State = %v, want %v", base.State, NodeStateHealthy)
		}
		if base.Metadata == nil {
			t.Error("Metadata should be initialized")
		}
	})

	t.Run("handles nil node", func(t *testing.T) {
		var node *ExtendedNode
		base := node.ToBaseNode()

		if base != nil {
			t.Errorf("expected nil, got %v", base)
		}
	})
}

func TestExtendedNodeList_Leader(t *testing.T) {
	t.Run("finds leader", func(t *testing.T) {
		list := ExtendedNodeList{
			{ID: 1, IsLeader: false},
			{ID: 2, IsLeader: true},
			{ID: 3, IsLeader: false},
		}

		leader := list.Leader()
		if leader == nil {
			t.Fatal("expected to find leader")
		}
		if leader.ID != 2 {
			t.Errorf("Leader ID = %d, want 2", leader.ID)
		}
	})

	t.Run("returns nil when no leader", func(t *testing.T) {
		list := ExtendedNodeList{
			{ID: 1, IsLeader: false},
			{ID: 2, IsLeader: false},
		}

		leader := list.Leader()
		if leader != nil {
			t.Errorf("expected nil, got %v", leader)
		}
	})

	t.Run("handles empty list", func(t *testing.T) {
		list := ExtendedNodeList{}
		leader := list.Leader()
		if leader != nil {
			t.Errorf("expected nil, got %v", leader)
		}
	})
}

func TestExtendedNodeList_Followers(t *testing.T) {
	list := ExtendedNodeList{
		{ID: 1, IsLeader: false},
		{ID: 2, IsLeader: true},
		{ID: 3, IsLeader: false},
	}

	followers := list.Followers()
	if len(followers) != 2 {
		t.Errorf("len(Followers()) = %d, want 2", len(followers))
	}

	for _, f := range followers {
		if f.IsLeader {
			t.Error("Followers() returned a leader")
		}
	}
}

func TestExtendedNodeList_Healthy(t *testing.T) {
	now := time.Now()
	list := ExtendedNodeList{
		{ID: 1, State: ExtNodeStateHealthy, LastSeen: now},
		{ID: 2, State: ExtNodeStateUnhealthy, LastSeen: now},
		{ID: 3, State: ExtNodeStateHealthy, LastSeen: now},
	}

	healthy := list.Healthy()
	if len(healthy) != 2 {
		t.Errorf("len(Healthy()) = %d, want 2", len(healthy))
	}
}

func TestExtendedNodeList_Count(t *testing.T) {
	list := ExtendedNodeList{{ID: 1}, {ID: 2}, {ID: 3}}
	if got := list.Count(); got != 3 {
		t.Errorf("Count() = %d, want 3", got)
	}
}

func TestExtendedNodeList_ByID(t *testing.T) {
	list := ExtendedNodeList{
		{ID: 1, Address: "addr1"},
		{ID: 2, Address: "addr2"},
		{ID: 3, Address: "addr3"},
	}

	t.Run("finds existing node", func(t *testing.T) {
		node := list.ByID(2)
		if node == nil {
			t.Fatal("expected to find node")
		}
		if node.Address != "addr2" {
			t.Errorf("Address = %s, want addr2", node.Address)
		}
	})

	t.Run("returns nil for non-existent node", func(t *testing.T) {
		node := list.ByID(99)
		if node != nil {
			t.Errorf("expected nil, got %v", node)
		}
	})
}

func TestExtendedNodeList_ByAddress(t *testing.T) {
	list := ExtendedNodeList{
		{ID: 1, Address: "addr1"},
		{ID: 2, Address: "addr2"},
	}

	t.Run("finds existing node", func(t *testing.T) {
		node := list.ByAddress("addr2")
		if node == nil {
			t.Fatal("expected to find node")
		}
		if node.ID != 2 {
			t.Errorf("ID = %d, want 2", node.ID)
		}
	})

	t.Run("returns nil for non-existent address", func(t *testing.T) {
		node := list.ByAddress("nonexistent")
		if node != nil {
			t.Errorf("expected nil, got %v", node)
		}
	})
}

func TestExtendedNodeList_ByRaftAddress(t *testing.T) {
	list := ExtendedNodeList{
		{ID: 1, RaftAddress: "raft1"},
		{ID: 2, RaftAddress: "raft2"},
	}

	t.Run("finds existing node", func(t *testing.T) {
		node := list.ByRaftAddress("raft2")
		if node == nil {
			t.Fatal("expected to find node")
		}
		if node.ID != 2 {
			t.Errorf("ID = %d, want 2", node.ID)
		}
	})

	t.Run("returns nil for non-existent address", func(t *testing.T) {
		node := list.ByRaftAddress("nonexistent")
		if node != nil {
			t.Errorf("expected nil, got %v", node)
		}
	})
}

func TestExtendedNodeList_SortByID(t *testing.T) {
	list := ExtendedNodeList{
		{ID: 3},
		{ID: 1},
		{ID: 2},
	}

	sorted := list.SortByID()

	if sorted[0].ID != 1 || sorted[1].ID != 2 || sorted[2].ID != 3 {
		t.Errorf("SortByID() = %v, expected ordered by ID", sorted)
	}

	// Original should not be modified
	if list[0].ID != 3 {
		t.Error("original list was modified")
	}
}

func TestExtendedNodeList_SortByJoinTime(t *testing.T) {
	now := time.Now()
	list := ExtendedNodeList{
		{ID: 1, JoinTime: now},
		{ID: 2, JoinTime: now.Add(-1 * time.Hour)},
		{ID: 3, JoinTime: now.Add(-2 * time.Hour)},
	}

	sorted := list.SortByJoinTime()

	if sorted[0].ID != 3 || sorted[1].ID != 2 || sorted[2].ID != 1 {
		t.Errorf("SortByJoinTime() order is wrong")
	}
}

func TestExtendedNodeList_Filter(t *testing.T) {
	now := time.Now()
	list := ExtendedNodeList{
		{ID: 1, State: ExtNodeStateHealthy, LastSeen: now},
		{ID: 2, State: ExtNodeStateUnhealthy, LastSeen: now},
		{ID: 3, State: ExtNodeStateHealthy, LastSeen: now},
	}

	filtered := list.Filter(func(n *ExtendedNode) bool {
		return n.State == ExtNodeStateHealthy
	})

	if len(filtered) != 2 {
		t.Errorf("len(Filter()) = %d, want 2", len(filtered))
	}
}

// Node Registry Tests

func TestExtendedNodeRegistry_Add(t *testing.T) {
	t.Run("adds valid node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		node := &ExtendedNode{ID: 1, Address: "addr1"}

		err := registry.Add(node)
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}

		if registry.Count() != 1 {
			t.Errorf("Count() = %d, want 1", registry.Count())
		}
	})

	t.Run("rejects nil node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.Add(nil)
		if err == nil {
			t.Error("Add(nil) should return error")
		}

		_, ok := err.(ErrNilNode)
		if !ok {
			t.Errorf("expected ErrNilNode, got %T", err)
		}
	})

	t.Run("rejects zero ID", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		node := &ExtendedNode{ID: 0}

		err := registry.Add(node)
		if err == nil {
			t.Error("Add() with zero ID should return error")
		}

		_, ok := err.(ErrInvalidNodeID)
		if !ok {
			t.Errorf("expected ErrInvalidNodeID, got %T", err)
		}
	})

	t.Run("updates existing node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		_ = registry.Add(&ExtendedNode{ID: 1, Address: "addr1"})
		_ = registry.Add(&ExtendedNode{ID: 1, Address: "addr2"})

		if registry.Count() != 1 {
			t.Errorf("Count() = %d, want 1", registry.Count())
		}

		node, _ := registry.Get(1)
		if node.Address != "addr2" {
			t.Errorf("Address = %s, want addr2", node.Address)
		}
	})
}

func TestExtendedNodeRegistry_Remove(t *testing.T) {
	t.Run("removes existing node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1})

		err := registry.Remove(1)
		if err != nil {
			t.Fatalf("Remove() error = %v", err)
		}

		if registry.Count() != 0 {
			t.Errorf("Count() = %d, want 0", registry.Count())
		}
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.Remove(99)
		if err == nil {
			t.Error("Remove() should return error for non-existent node")
		}

		_, ok := err.(ErrNodeNotFound)
		if !ok {
			t.Errorf("expected ErrNodeNotFound, got %T", err)
		}
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.Remove(0)
		if err == nil {
			t.Error("Remove(0) should return error")
		}

		_, ok := err.(ErrInvalidNodeID)
		if !ok {
			t.Errorf("expected ErrInvalidNodeID, got %T", err)
		}
	})
}

func TestExtendedNodeRegistry_Get(t *testing.T) {
	t.Run("gets existing node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1, Address: "addr1"})

		node, err := registry.Get(1)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}

		if node.Address != "addr1" {
			t.Errorf("Address = %s, want addr1", node.Address)
		}
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		_, err := registry.Get(99)
		if err == nil {
			t.Error("Get() should return error for non-existent node")
		}
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		_, err := registry.Get(0)
		if err == nil {
			t.Error("Get(0) should return error")
		}
	})

	t.Run("returns clone not original", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1, Address: "addr1"})

		node, _ := registry.Get(1)
		node.Address = "modified"

		original, _ := registry.Get(1)
		if original.Address != "addr1" {
			t.Error("Get() should return a clone")
		}
	})
}

func TestExtendedNodeRegistry_List(t *testing.T) {
	registry := NewExtendedNodeRegistry()
	_ = registry.Add(&ExtendedNode{ID: 1})
	_ = registry.Add(&ExtendedNode{ID: 2})
	_ = registry.Add(&ExtendedNode{ID: 3})

	list := registry.List()

	if len(list) != 3 {
		t.Errorf("List() length = %d, want 3", len(list))
	}
}

func TestExtendedNodeRegistry_UpdateState(t *testing.T) {
	t.Run("updates state", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1, State: ExtNodeStateUnknown})

		err := registry.UpdateState(1, ExtNodeStateHealthy)
		if err != nil {
			t.Fatalf("UpdateState() error = %v", err)
		}

		node, _ := registry.Get(1)
		if node.State != ExtNodeStateHealthy {
			t.Errorf("State = %v, want %v", node.State, ExtNodeStateHealthy)
		}
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.UpdateState(99, ExtNodeStateHealthy)
		if err == nil {
			t.Error("UpdateState() should return error for non-existent node")
		}
	})

	t.Run("returns error for invalid state", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1})

		err := registry.UpdateState(1, ExtendedNodeState("invalid"))
		if err == nil {
			t.Error("UpdateState() should return error for invalid state")
		}
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.UpdateState(0, ExtNodeStateHealthy)
		if err == nil {
			t.Error("UpdateState(0, ...) should return error")
		}
	})
}

func TestExtendedNodeRegistry_SetLeader(t *testing.T) {
	t.Run("sets leader", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1, IsLeader: true})
		_ = registry.Add(&ExtendedNode{ID: 2, IsLeader: false})

		err := registry.SetLeader(2)
		if err != nil {
			t.Fatalf("SetLeader() error = %v", err)
		}

		node1, _ := registry.Get(1)
		node2, _ := registry.Get(2)

		if node1.IsLeader {
			t.Error("node 1 should no longer be leader")
		}
		if !node2.IsLeader {
			t.Error("node 2 should be leader")
		}
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.SetLeader(99)
		if err == nil {
			t.Error("SetLeader() should return error for non-existent node")
		}
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.SetLeader(0)
		if err == nil {
			t.Error("SetLeader(0) should return error")
		}
	})
}

func TestExtendedNodeRegistry_ClearLeader(t *testing.T) {
	registry := NewExtendedNodeRegistry()
	_ = registry.Add(&ExtendedNode{ID: 1, IsLeader: true})
	_ = registry.Add(&ExtendedNode{ID: 2, IsLeader: false})

	registry.ClearLeader()

	node1, _ := registry.Get(1)
	node2, _ := registry.Get(2)

	if node1.IsLeader || node2.IsLeader {
		t.Error("ClearLeader() should clear all leader flags")
	}
}

func TestExtendedNodeRegistry_Count(t *testing.T) {
	registry := NewExtendedNodeRegistry()

	if registry.Count() != 0 {
		t.Errorf("empty registry Count() = %d, want 0", registry.Count())
	}

	_ = registry.Add(&ExtendedNode{ID: 1})
	_ = registry.Add(&ExtendedNode{ID: 2})

	if registry.Count() != 2 {
		t.Errorf("Count() = %d, want 2", registry.Count())
	}
}

func TestExtendedNodeRegistry_HealthyCount(t *testing.T) {
	now := time.Now()
	registry := NewExtendedNodeRegistry()
	_ = registry.Add(&ExtendedNode{ID: 1, State: ExtNodeStateHealthy, LastSeen: now})
	_ = registry.Add(&ExtendedNode{ID: 2, State: ExtNodeStateUnhealthy, LastSeen: now})
	_ = registry.Add(&ExtendedNode{ID: 3, State: ExtNodeStateHealthy, LastSeen: now})

	if registry.HealthyCount() != 2 {
		t.Errorf("HealthyCount() = %d, want 2", registry.HealthyCount())
	}
}

func TestExtendedNodeRegistry_UpdateLastSeen(t *testing.T) {
	t.Run("updates last seen", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		oldTime := time.Now().Add(-1 * time.Hour)
		_ = registry.Add(&ExtendedNode{ID: 1, LastSeen: oldTime})

		err := registry.UpdateLastSeen(1)
		if err != nil {
			t.Fatalf("UpdateLastSeen() error = %v", err)
		}

		node, _ := registry.Get(1)
		if node.LastSeen.Before(oldTime.Add(59 * time.Minute)) {
			t.Error("LastSeen was not updated")
		}
	})

	t.Run("returns error for non-existent node", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.UpdateLastSeen(99)
		if err == nil {
			t.Error("UpdateLastSeen() should return error for non-existent node")
		}
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		err := registry.UpdateLastSeen(0)
		if err == nil {
			t.Error("UpdateLastSeen(0) should return error")
		}
	})
}

func TestExtendedNodeRegistry_GetLeader(t *testing.T) {
	t.Run("returns leader", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1, IsLeader: false})
		_ = registry.Add(&ExtendedNode{ID: 2, IsLeader: true})

		leader, err := registry.GetLeader()
		if err != nil {
			t.Fatalf("GetLeader() error = %v", err)
		}

		if leader.ID != 2 {
			t.Errorf("leader ID = %d, want 2", leader.ID)
		}
	})

	t.Run("returns error when no leader", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()
		_ = registry.Add(&ExtendedNode{ID: 1, IsLeader: false})

		_, err := registry.GetLeader()
		if err == nil {
			t.Error("GetLeader() should return error when no leader")
		}

		_, ok := err.(ErrNoLeader)
		if !ok {
			t.Errorf("expected ErrNoLeader, got %T", err)
		}
	})
}

func TestExtendedNodeRegistry_Concurrent(t *testing.T) {
	t.Run("concurrent add operations", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		var wg sync.WaitGroup
		for i := 1; i <= 100; i++ {
			wg.Add(1)
			go func(id uint64) {
				defer wg.Done()
				_ = registry.Add(&ExtendedNode{ID: id})
			}(uint64(i))
		}
		wg.Wait()

		if registry.Count() != 100 {
			t.Errorf("Count() = %d, want 100", registry.Count())
		}
	})

	t.Run("concurrent read/write operations", func(t *testing.T) {
		registry := NewExtendedNodeRegistry()

		// Add initial nodes
		for i := uint64(1); i <= 10; i++ {
			_ = registry.Add(&ExtendedNode{ID: i, State: ExtNodeStateUnknown})
		}

		var wg sync.WaitGroup

		// Concurrent reads
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = registry.List()
				_ = registry.Count()
				_ = registry.HealthyCount()
				_, _ = registry.Get(1)
			}()
		}

		// Concurrent writes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				id := uint64((idx % 10) + 1)
				_ = registry.UpdateState(id, ExtNodeStateHealthy)
				_ = registry.UpdateLastSeen(id)
			}(i)
		}

		wg.Wait()
	})
}
