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
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkExtendedNodeList_Leader benchmarks finding the leader in a node list.
func BenchmarkExtendedNodeList_Leader(b *testing.B) {
	sizes := []int{3, 5, 10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d", size), func(b *testing.B) {
			nl := createExtendedNodeList(size, size/2) // Leader at middle position
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = nl.Leader()
			}
		})
	}
}

// BenchmarkExtendedNodeList_Leader_Parallel benchmarks concurrent leader lookups.
func BenchmarkExtendedNodeList_Leader_Parallel(b *testing.B) {
	nl := createExtendedNodeList(10, 5)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = nl.Leader()
		}
	})
}

// BenchmarkExtendedNodeList_Filter benchmarks filtering nodes by predicate.
func BenchmarkExtendedNodeList_Filter(b *testing.B) {
	sizes := []int{10, 50, 100, 500}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d", size), func(b *testing.B) {
			nl := createExtendedNodeList(size, -1)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = nl.Filter(func(n *ExtendedNode) bool {
					return n.State == ExtNodeStateHealthy
				})
			}
		})
	}
}

// BenchmarkExtendedNodeList_Filter_Parallel benchmarks concurrent filtering.
func BenchmarkExtendedNodeList_Filter_Parallel(b *testing.B) {
	nl := createExtendedNodeList(100, -1)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = nl.Filter(func(n *ExtendedNode) bool {
				return n.State == ExtNodeStateHealthy
			})
		}
	})
}

// BenchmarkExtendedNodeList_Healthy benchmarks getting healthy nodes.
func BenchmarkExtendedNodeList_Healthy(b *testing.B) {
	sizes := []int{10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d", size), func(b *testing.B) {
			nl := createExtendedNodeList(size, -1)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = nl.Healthy()
			}
		})
	}
}

// BenchmarkExtendedNodeList_ByID benchmarks finding a node by ID.
func BenchmarkExtendedNodeList_ByID(b *testing.B) {
	sizes := []int{10, 50, 100, 500}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d_First", size), func(b *testing.B) {
			nl := createExtendedNodeList(size, -1)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = nl.ByID(1)
			}
		})

		b.Run(fmt.Sprintf("Nodes_%d_Last", size), func(b *testing.B) {
			nl := createExtendedNodeList(size, -1)
			targetID := uint64(size)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = nl.ByID(targetID)
			}
		})
	}
}

// BenchmarkExtendedNodeList_SortByID benchmarks sorting nodes by ID.
func BenchmarkExtendedNodeList_SortByID(b *testing.B) {
	sizes := []int{10, 50, 100, 500}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d", size), func(b *testing.B) {
			nl := createExtendedNodeList(size, -1)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = nl.SortByID()
			}
		})
	}
}

// BenchmarkExtendedNodeRegistry_Add benchmarks adding nodes to the registry.
func BenchmarkExtendedNodeRegistry_Add(b *testing.B) {
	b.Run("Sequential", func(b *testing.B) {
		reg := NewExtendedNodeRegistry()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			node := &ExtendedNode{
				ID:       uint64(i + 1),
				Address:  fmt.Sprintf("192.168.1.%d:8080", (i%254)+1),
				State:    ExtNodeStateHealthy,
				LastSeen: time.Now(),
				JoinTime: time.Now(),
			}
			_ = reg.Add(node)
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		reg := NewExtendedNodeRegistry()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				counter++
				node := &ExtendedNode{
					ID:       uint64(counter),
					Address:  fmt.Sprintf("192.168.1.%d:8080", (counter%254)+1),
					State:    ExtNodeStateHealthy,
					LastSeen: time.Now(),
					JoinTime: time.Now(),
				}
				_ = reg.Add(node)
			}
		})
	})
}

// BenchmarkExtendedNodeRegistry_Get benchmarks getting nodes from the registry.
func BenchmarkExtendedNodeRegistry_Get(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d", size), func(b *testing.B) {
			reg := NewExtendedNodeRegistry()
			for i := 1; i <= size; i++ {
				node := &ExtendedNode{
					ID:       uint64(i),
					Address:  fmt.Sprintf("192.168.1.%d:8080", (i%254)+1),
					State:    ExtNodeStateHealthy,
					LastSeen: time.Now(),
					JoinTime: time.Now(),
				}
				_ = reg.Add(node)
			}

			targetID := uint64(size / 2)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, _ = reg.Get(targetID)
			}
		})
	}
}

// BenchmarkExtendedNodeRegistry_Get_Parallel benchmarks concurrent node retrieval.
func BenchmarkExtendedNodeRegistry_Get_Parallel(b *testing.B) {
	reg := NewExtendedNodeRegistry()
	for i := 1; i <= 100; i++ {
		node := &ExtendedNode{
			ID:       uint64(i),
			Address:  fmt.Sprintf("192.168.1.%d:8080", (i%254)+1),
			State:    ExtNodeStateHealthy,
			LastSeen: time.Now(),
			JoinTime: time.Now(),
		}
		_ = reg.Add(node)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			_, _ = reg.Get(uint64((counter % 100) + 1))
		}
	})
}

// BenchmarkExtendedNodeRegistry_List benchmarks listing all nodes.
func BenchmarkExtendedNodeRegistry_List(b *testing.B) {
	sizes := []int{10, 50, 100, 500}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Nodes_%d", size), func(b *testing.B) {
			reg := NewExtendedNodeRegistry()
			for i := 1; i <= size; i++ {
				node := &ExtendedNode{
					ID:       uint64(i),
					Address:  fmt.Sprintf("192.168.1.%d:8080", (i%254)+1),
					State:    ExtNodeStateHealthy,
					LastSeen: time.Now(),
					JoinTime: time.Now(),
				}
				_ = reg.Add(node)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = reg.List()
			}
		})
	}
}

// BenchmarkExtendedNodeRegistry_UpdateState benchmarks state updates.
func BenchmarkExtendedNodeRegistry_UpdateState(b *testing.B) {
	reg := NewExtendedNodeRegistry()
	for i := 1; i <= 100; i++ {
		node := &ExtendedNode{
			ID:       uint64(i),
			Address:  fmt.Sprintf("192.168.1.%d:8080", (i%254)+1),
			State:    ExtNodeStateHealthy,
			LastSeen: time.Now(),
			JoinTime: time.Now(),
		}
		_ = reg.Add(node)
	}

	states := []ExtendedNodeState{
		ExtNodeStateHealthy,
		ExtNodeStateUnhealthy,
		ExtNodeStateUnreachable,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		nodeID := uint64((i % 100) + 1)
		state := states[i%len(states)]
		_ = reg.UpdateState(nodeID, state)
	}
}

// BenchmarkRaftStateTransition benchmarks Raft state transitions.
func BenchmarkRaftStateTransition(b *testing.B) {
	transitions := []struct {
		from RaftClusterState
		to   RaftClusterState
	}{
		{RaftStateUninitialized, RaftStateBootstrapping},
		{RaftStateBootstrapping, RaftStateFollowerRole},
		{RaftStateFollowerRole, RaftStateCandidateRole},
		{RaftStateCandidateRole, RaftStateLeaderRole},
		{RaftStateLeaderRole, RaftStateFollowerRole},
	}

	for _, tt := range transitions {
		b.Run(fmt.Sprintf("%s_to_%s", tt.from, tt.to), func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				sm := NewRaftStateManager()
				// Set initial state
				ctx := context.Background()
				_ = sm.SetState(ctx, tt.from)
				// Transition to target
				_ = sm.SetState(ctx, tt.to)
			}
		})
	}
}

// BenchmarkRaftStateManager_GetState benchmarks state retrieval.
func BenchmarkRaftStateManager_GetState(b *testing.B) {
	sm := NewRaftStateManager()
	_ = sm.SetState(context.Background(), RaftStateFollowerRole)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = sm.GetState()
	}
}

// BenchmarkRaftStateManager_GetState_Parallel benchmarks concurrent state retrieval.
func BenchmarkRaftStateManager_GetState_Parallel(b *testing.B) {
	sm := NewRaftStateManager()
	_ = sm.SetState(context.Background(), RaftStateFollowerRole)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = sm.GetState()
		}
	})
}

// BenchmarkRaftStateManager_GetStatus benchmarks status retrieval.
func BenchmarkRaftStateManager_GetStatus(b *testing.B) {
	sm := NewRaftStateManager()
	ctx := context.Background()
	_ = sm.UpdateStatus(ctx, func(s *RaftClusterStatus) {
		s.NodeID = 1
		s.LeaderID = 1
		s.Term = 10
		s.NodeCount = 3
		s.HealthyCount = 3
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = sm.GetStatus()
	}
}

// BenchmarkRaftClusterState_CanTransitionTo benchmarks transition validation.
func BenchmarkRaftClusterState_CanTransitionTo(b *testing.B) {
	states := []RaftClusterState{
		RaftStateUninitialized,
		RaftStateBootstrapping,
		RaftStateFollowerRole,
		RaftStateCandidateRole,
		RaftStateLeaderRole,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		from := states[i%len(states)]
		to := states[(i+1)%len(states)]
		_ = from.CanTransitionTo(to)
	}
}

// BenchmarkRaftClusterState_IsOperational benchmarks operational state checks.
func BenchmarkRaftClusterState_IsOperational(b *testing.B) {
	states := AllRaftClusterStates()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		state := states[i%len(states)]
		_ = state.IsOperational()
	}
}

// BenchmarkExtendedNode_Clone benchmarks node cloning.
func BenchmarkExtendedNode_Clone(b *testing.B) {
	node := &ExtendedNode{
		ID:          1,
		Address:     "192.168.1.1:8080",
		RaftAddress: "192.168.1.1:9000",
		State:       ExtNodeStateHealthy,
		IsLeader:    true,
		LastSeen:    time.Now(),
		JoinTime:    time.Now().Add(-24 * time.Hour),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = node.Clone()
	}
}

// BenchmarkExtendedNode_IsHealthy benchmarks health checks.
func BenchmarkExtendedNode_IsHealthy(b *testing.B) {
	node := &ExtendedNode{
		State:    ExtNodeStateHealthy,
		LastSeen: time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = node.IsHealthy()
	}
}

// createExtendedNodeList creates a test node list for benchmarks.
// leaderIdx specifies which node should be the leader (-1 for no leader).
func createExtendedNodeList(size int, leaderIdx int) ExtendedNodeList {
	nodes := make(ExtendedNodeList, size)
	now := time.Now()

	for i := 0; i < size; i++ {
		state := ExtNodeStateHealthy
		if i%5 == 0 {
			state = ExtNodeStateUnhealthy
		}

		nodes[i] = ExtendedNode{
			ID:          uint64(i + 1),
			Address:     fmt.Sprintf("192.168.1.%d:8080", (i%254)+1),
			RaftAddress: fmt.Sprintf("192.168.1.%d:9000", (i%254)+1),
			State:       state,
			IsLeader:    i == leaderIdx,
			LastSeen:    now,
			JoinTime:    now.Add(-time.Duration(i) * time.Hour),
		}
	}

	return nodes
}
