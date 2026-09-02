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
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewQuicBaaSStateNotifier(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		require.NotNil(t, notifier)
		defer notifier.Close()

		assert.Equal(t, defaultSubscriberBufferSize, notifier.bufferSize)
		stats := notifier.Stats()
		assert.Equal(t, 0, stats.SubscriberCount)
		assert.Equal(t, uint64(0), stats.NotifyCount)
		assert.Equal(t, uint64(0), stats.DropCount)
		assert.False(t, stats.Closed)
	})

	t.Run("custom buffer size", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(512))
		require.NotNil(t, notifier)
		defer notifier.Close()

		assert.Equal(t, 512, notifier.bufferSize)
	})

	t.Run("custom slow consumer threshold", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier(WithSlowConsumerThreshold(50))
		require.NotNil(t, notifier)
		defer notifier.Close()
	})

	t.Run("invalid buffer size uses default", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(-1))
		require.NotNil(t, notifier)
		defer notifier.Close()

		assert.Equal(t, defaultSubscriberBufferSize, notifier.bufferSize)
	})
}

func TestQuicBaaSStateNotifier_Subscribe(t *testing.T) {
	t.Run("subscribe without filter", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		ch, unsubscribe := notifier.Subscribe(NotificationFilter{})
		require.NotNil(t, ch)
		require.NotNil(t, unsubscribe)

		stats := notifier.Stats()
		assert.Equal(t, 1, stats.SubscriberCount)

		unsubscribe()

		// Give time for cleanup.
		time.Sleep(10 * time.Millisecond)
		stats = notifier.Stats()
		assert.Equal(t, 0, stats.SubscriberCount)
	})

	t.Run("subscribe with entity type filter", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		filter := NotificationFilter{
			EntityTypes: []EntityType{EntityTypeBridge},
		}

		ch, unsubscribe := notifier.Subscribe(filter)
		defer unsubscribe()

		require.NotNil(t, ch)
	})

	t.Run("subscribe with operation filter", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		filter := NotificationFilter{
			Operations: []OperationType{OpTypeCreateBridge, OpTypeUpdateBridge},
		}

		ch, unsubscribe := notifier.Subscribe(filter)
		defer unsubscribe()

		require.NotNil(t, ch)
	})

	t.Run("subscribe with combined filter", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		filter := NotificationFilter{
			EntityTypes: []EntityType{EntityTypeBridge, EntityTypePort},
			Operations:  []OperationType{OpTypeCreateBridge, OpTypeCreatePort},
		}

		ch, unsubscribe := notifier.Subscribe(filter)
		defer unsubscribe()

		require.NotNil(t, ch)
	})

	t.Run("multiple subscribers", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		_, unsub1 := notifier.Subscribe(NotificationFilter{})
		_, unsub2 := notifier.Subscribe(NotificationFilter{})
		_, unsub3 := notifier.Subscribe(NotificationFilter{})

		stats := notifier.Stats()
		assert.Equal(t, 3, stats.SubscriberCount)

		unsub1()
		time.Sleep(10 * time.Millisecond)
		stats = notifier.Stats()
		assert.Equal(t, 2, stats.SubscriberCount)

		unsub2()
		unsub3()
		time.Sleep(10 * time.Millisecond)
		stats = notifier.Stats()
		assert.Equal(t, 0, stats.SubscriberCount)
	})

	t.Run("subscribe to closed notifier returns closed channel", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		notifier.Close()

		ch, unsubscribe := notifier.Subscribe(NotificationFilter{})
		defer unsubscribe()

		// Channel should be closed immediately.
		select {
		case _, ok := <-ch:
			assert.False(t, ok, "channel should be closed")
		default:
			t.Error("channel should be closed, not blocking")
		}
	})
}

func TestQuicBaaSStateNotifier_Notify(t *testing.T) {
	t.Run("notify without subscribers", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		change := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
		err := notifier.Notify(change)

		require.NoError(t, err)
		stats := notifier.Stats()
		assert.Equal(t, uint64(1), stats.NotifyCount)
	})

	t.Run("notify single subscriber", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		ch, unsubscribe := notifier.Subscribe(NotificationFilter{})
		defer unsubscribe()

		bridge := &BridgeState{ID: "br-1", Name: "test"}
		change := NewBridgeCreateChange(bridge, "node-1")

		err := notifier.Notify(change)
		require.NoError(t, err)

		select {
		case received := <-ch:
			assert.Equal(t, EntityTypeBridge, received.EntityType)
			assert.Equal(t, OpTypeCreateBridge, received.Operation)
			assert.Equal(t, "br-1", received.EntityID)
			assert.Equal(t, "node-1", received.NodeID)
			assert.NotNil(t, received.Entity)
		case <-time.After(100 * time.Millisecond):
			t.Error("timeout waiting for notification")
		}
	})

	t.Run("notify multiple subscribers", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		ch1, unsub1 := notifier.Subscribe(NotificationFilter{})
		defer unsub1()

		ch2, unsub2 := notifier.Subscribe(NotificationFilter{})
		defer unsub2()

		change := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
		err := notifier.Notify(change)
		require.NoError(t, err)

		for i, ch := range []<-chan StateChange{ch1, ch2} {
			select {
			case received := <-ch:
				assert.Equal(t, "br-1", received.EntityID, "subscriber %d", i)
			case <-time.After(100 * time.Millisecond):
				t.Errorf("timeout waiting for notification on subscriber %d", i)
			}
		}
	})

	t.Run("filter by entity type", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		bridgeCh, unsub1 := notifier.Subscribe(NotificationFilter{
			EntityTypes: []EntityType{EntityTypeBridge},
		})
		defer unsub1()

		portCh, unsub2 := notifier.Subscribe(NotificationFilter{
			EntityTypes: []EntityType{EntityTypePort},
		})
		defer unsub2()

		// Send bridge change.
		bridgeChange := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
		require.NoError(t, notifier.Notify(bridgeChange))

		// Bridge subscriber should receive it.
		select {
		case received := <-bridgeCh:
			assert.Equal(t, EntityTypeBridge, received.EntityType)
		case <-time.After(100 * time.Millisecond):
			t.Error("bridge subscriber should receive notification")
		}

		// Port subscriber should not receive it.
		select {
		case <-portCh:
			t.Error("port subscriber should not receive bridge notification")
		case <-time.After(50 * time.Millisecond):
			// Expected timeout.
		}
	})

	t.Run("filter by operation type", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		createCh, unsub1 := notifier.Subscribe(NotificationFilter{
			Operations: []OperationType{OpTypeCreateBridge},
		})
		defer unsub1()

		deleteCh, unsub2 := notifier.Subscribe(NotificationFilter{
			Operations: []OperationType{OpTypeDeleteBridge},
		})
		defer unsub2()

		// Send create change.
		createChange := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
		require.NoError(t, notifier.Notify(createChange))

		// Create subscriber should receive it.
		select {
		case received := <-createCh:
			assert.Equal(t, OpTypeCreateBridge, received.Operation)
		case <-time.After(100 * time.Millisecond):
			t.Error("create subscriber should receive notification")
		}

		// Delete subscriber should not receive it.
		select {
		case <-deleteCh:
			t.Error("delete subscriber should not receive create notification")
		case <-time.After(50 * time.Millisecond):
			// Expected timeout.
		}
	})

	t.Run("filter by combined entity and operation", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		ch, unsubscribe := notifier.Subscribe(NotificationFilter{
			EntityTypes: []EntityType{EntityTypeBridge},
			Operations:  []OperationType{OpTypeCreateBridge},
		})
		defer unsubscribe()

		// Should receive: bridge create.
		createChange := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
		require.NoError(t, notifier.Notify(createChange))

		select {
		case <-ch:
			// Expected.
		case <-time.After(100 * time.Millisecond):
			t.Error("should receive bridge create")
		}

		// Should not receive: bridge update.
		updateChange := NewBridgeUpdateChange(&BridgeState{ID: "br-1", Name: "test-updated"}, "node-1")
		require.NoError(t, notifier.Notify(updateChange))

		select {
		case <-ch:
			t.Error("should not receive bridge update")
		case <-time.After(50 * time.Millisecond):
			// Expected timeout.
		}

		// Should not receive: port create.
		portChange := NewPortCreateChange(&PortState{ID: "port-1", Name: "test", BridgeID: "br-1"}, "node-1")
		require.NoError(t, notifier.Notify(portChange))

		select {
		case <-ch:
			t.Error("should not receive port create")
		case <-time.After(50 * time.Millisecond):
			// Expected timeout.
		}
	})

	t.Run("notify closed notifier returns error", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		notifier.Close()

		change := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
		err := notifier.Notify(change)

		require.Error(t, err)
		var closedErr ErrNotifierClosed
		assert.ErrorAs(t, err, &closedErr)
	})
}

func TestQuicBaaSStateNotifier_SlowConsumer(t *testing.T) {
	t.Run("slow consumer does not block other subscribers", func(t *testing.T) {
		// Use small buffer to trigger slow consumer behavior.
		notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(2))
		defer notifier.Close()

		// Slow consumer that never reads.
		_, slowUnsub := notifier.Subscribe(NotificationFilter{})
		defer slowUnsub()

		// Fast consumer that reads immediately with larger buffer.
		fastCh, fastUnsub := notifier.Subscribe(NotificationFilter{})
		defer fastUnsub()

		// Send more notifications than the slow consumer's buffer.
		// The fast consumer should still receive them because we use non-blocking sends.
		notifyCount := 10
		for i := 0; i < notifyCount; i++ {
			change := NewBridgeCreateChange(&BridgeState{
				ID:   "br-" + string(rune('0'+i)),
				Name: "test",
			}, "node-1")
			err := notifier.Notify(change)
			require.NoError(t, err)
		}

		// Drain the fast consumer's channel.
		receivedCount := 0
		timeout := time.After(500 * time.Millisecond)
	drainLoop:
		for {
			select {
			case <-fastCh:
				receivedCount++
			case <-timeout:
				break drainLoop
			}
		}

		// Fast consumer should have received messages without being blocked.
		assert.GreaterOrEqual(t, receivedCount, 1, "fast consumer should receive some notifications")

		stats := notifier.Stats()
		// Slow consumer should have dropped notifications since its buffer is only 2.
		assert.Greater(t, stats.DropCount, uint64(0), "should have dropped notifications for slow consumer")
	})
}

func TestQuicBaaSStateNotifier_Close(t *testing.T) {
	t.Run("close notifier closes all subscriber channels", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()

		ch1, _ := notifier.Subscribe(NotificationFilter{})
		ch2, _ := notifier.Subscribe(NotificationFilter{})

		err := notifier.Close()
		require.NoError(t, err)

		// Channels should be closed.
		time.Sleep(10 * time.Millisecond)

		_, ok1 := <-ch1
		assert.False(t, ok1, "channel 1 should be closed")

		_, ok2 := <-ch2
		assert.False(t, ok2, "channel 2 should be closed")

		stats := notifier.Stats()
		assert.True(t, stats.Closed)
	})

	t.Run("double close returns error", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()

		err1 := notifier.Close()
		require.NoError(t, err1)

		err2 := notifier.Close()
		require.Error(t, err2)
		var closedErr ErrNotifierClosed
		assert.ErrorAs(t, err2, &closedErr)
	})
}

func TestQuicBaaSStateNotifier_Unsubscribe(t *testing.T) {
	t.Run("unsubscribe closes channel", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		ch, unsubscribe := notifier.Subscribe(NotificationFilter{})
		unsubscribe()

		// Channel should be closed.
		time.Sleep(10 * time.Millisecond)
		_, ok := <-ch
		assert.False(t, ok, "channel should be closed after unsubscribe")
	})

	t.Run("double unsubscribe is safe", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		_, unsubscribe := notifier.Subscribe(NotificationFilter{})
		unsubscribe()
		unsubscribe() // Should not panic.
	})

	t.Run("unsubscribe after close is safe", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()

		_, unsubscribe := notifier.Subscribe(NotificationFilter{})
		notifier.Close()
		unsubscribe() // Should not panic.
	})
}

func TestQuicBaaSStateNotifier_Concurrency(t *testing.T) {
	t.Run("concurrent subscribe and unsubscribe", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		var wg sync.WaitGroup
		subscriberCount := 100

		for i := 0; i < subscriberCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, unsubscribe := notifier.Subscribe(NotificationFilter{})
				time.Sleep(time.Millisecond * time.Duration(1))
				unsubscribe()
			}()
		}

		wg.Wait()

		stats := notifier.Stats()
		assert.Equal(t, 0, stats.SubscriberCount)
	})

	t.Run("concurrent notify", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		ch, unsubscribe := notifier.Subscribe(NotificationFilter{})
		defer unsubscribe()

		notifyCount := 100
		var wg sync.WaitGroup

		for i := 0; i < notifyCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				change := NewBridgeCreateChange(&BridgeState{
					ID:   "br-" + string(rune('0'+id%10)),
					Name: "test",
				}, "node-1")
				err := notifier.Notify(change)
				assert.NoError(t, err)
			}(i)
		}

		wg.Wait()

		stats := notifier.Stats()
		assert.Equal(t, uint64(notifyCount), stats.NotifyCount)

		// Drain the channel.
		received := 0
		for {
			select {
			case <-ch:
				received++
			case <-time.After(100 * time.Millisecond):
				goto done
			}
		}
	done:
		assert.GreaterOrEqual(t, received, 1)
	})

	t.Run("concurrent subscribe notify unsubscribe", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		var wg sync.WaitGroup
		var receivedCount atomic.Int64
		iterations := 50

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ch, unsubscribe := notifier.Subscribe(NotificationFilter{})
				defer unsubscribe()

				// Receive for a short time.
				timeout := time.After(50 * time.Millisecond)
				for {
					select {
					case <-ch:
						receivedCount.Add(1)
					case <-timeout:
						return
					}
				}
			}()

			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					change := NewBridgeCreateChange(&BridgeState{
						ID:   "br-" + string(rune('a'+id%26)),
						Name: "test",
					}, "node-1")
					notifier.Notify(change)
				}
			}(i)
		}

		wg.Wait()

		// Just verify no panics or deadlocks.
		stats := notifier.Stats()
		assert.GreaterOrEqual(t, stats.NotifyCount, uint64(1))
	})
}

func TestNotificationFilter_Matches(t *testing.T) {
	t.Run("empty filter matches everything", func(t *testing.T) {
		filter := NotificationFilter{}

		testCases := []StateChange{
			{EntityType: EntityTypeBridge, Operation: OpTypeCreateBridge},
			{EntityType: EntityTypePort, Operation: OpTypeUpdatePort},
			{EntityType: EntityTypeFlow, Operation: OpTypeDeleteFlow},
			{EntityType: EntityTypeVLAN, Operation: OpTypeCreateVLAN},
		}

		for _, tc := range testCases {
			assert.True(t, filter.Matches(tc))
		}
	})

	t.Run("entity type filter", func(t *testing.T) {
		filter := NotificationFilter{
			EntityTypes: []EntityType{EntityTypeBridge, EntityTypePort},
		}

		assert.True(t, filter.Matches(StateChange{EntityType: EntityTypeBridge, Operation: OpTypeCreateBridge}))
		assert.True(t, filter.Matches(StateChange{EntityType: EntityTypePort, Operation: OpTypeCreatePort}))
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypeFlow, Operation: OpTypeCreateFlow}))
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypeVLAN, Operation: OpTypeCreateVLAN}))
	})

	t.Run("operation filter", func(t *testing.T) {
		filter := NotificationFilter{
			Operations: []OperationType{OpTypeCreateBridge, OpTypeCreatePort},
		}

		assert.True(t, filter.Matches(StateChange{EntityType: EntityTypeBridge, Operation: OpTypeCreateBridge}))
		assert.True(t, filter.Matches(StateChange{EntityType: EntityTypePort, Operation: OpTypeCreatePort}))
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypeBridge, Operation: OpTypeUpdateBridge}))
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypeBridge, Operation: OpTypeDeleteBridge}))
	})

	t.Run("combined filter requires both to match", func(t *testing.T) {
		filter := NotificationFilter{
			EntityTypes: []EntityType{EntityTypeBridge},
			Operations:  []OperationType{OpTypeCreateBridge},
		}

		// Both match.
		assert.True(t, filter.Matches(StateChange{EntityType: EntityTypeBridge, Operation: OpTypeCreateBridge}))

		// Entity matches but operation doesn't.
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypeBridge, Operation: OpTypeUpdateBridge}))

		// Operation matches but entity doesn't.
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypePort, Operation: OpTypeCreateBridge}))

		// Neither matches.
		assert.False(t, filter.Matches(StateChange{EntityType: EntityTypeFlow, Operation: OpTypeDeleteFlow}))
	})
}

func TestStateChangeHelpers(t *testing.T) {
	t.Run("NewBridgeCreateChange", func(t *testing.T) {
		bridge := &BridgeState{ID: "br-1", Name: "test"}
		change := NewBridgeCreateChange(bridge, "node-1")

		assert.Equal(t, EntityTypeBridge, change.EntityType)
		assert.Equal(t, OpTypeCreateBridge, change.Operation)
		assert.Equal(t, "br-1", change.EntityID)
		assert.Equal(t, "node-1", change.NodeID)
		assert.Equal(t, bridge, change.Entity)
		assert.False(t, change.Timestamp.IsZero())
	})

	t.Run("NewBridgeUpdateChange", func(t *testing.T) {
		bridge := &BridgeState{ID: "br-1", Name: "test"}
		change := NewBridgeUpdateChange(bridge, "node-1")

		assert.Equal(t, EntityTypeBridge, change.EntityType)
		assert.Equal(t, OpTypeUpdateBridge, change.Operation)
		assert.Equal(t, "br-1", change.EntityID)
	})

	t.Run("NewBridgeDeleteChange", func(t *testing.T) {
		change := NewBridgeDeleteChange("br-1", "node-1")

		assert.Equal(t, EntityTypeBridge, change.EntityType)
		assert.Equal(t, OpTypeDeleteBridge, change.Operation)
		assert.Equal(t, "br-1", change.EntityID)
		assert.Nil(t, change.Entity)
	})

	t.Run("NewPortCreateChange", func(t *testing.T) {
		port := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}
		change := NewPortCreateChange(port, "node-1")

		assert.Equal(t, EntityTypePort, change.EntityType)
		assert.Equal(t, OpTypeCreatePort, change.Operation)
		assert.Equal(t, "port-1", change.EntityID)
	})

	t.Run("NewPortUpdateChange", func(t *testing.T) {
		port := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}
		change := NewPortUpdateChange(port, "node-1")

		assert.Equal(t, EntityTypePort, change.EntityType)
		assert.Equal(t, OpTypeUpdatePort, change.Operation)
	})

	t.Run("NewPortDeleteChange", func(t *testing.T) {
		change := NewPortDeleteChange("port-1", "node-1")

		assert.Equal(t, EntityTypePort, change.EntityType)
		assert.Equal(t, OpTypeDeletePort, change.Operation)
		assert.Equal(t, "port-1", change.EntityID)
		assert.Nil(t, change.Entity)
	})

	t.Run("NewFlowCreateChange", func(t *testing.T) {
		flow := &FlowState{ID: "flow-1", BridgeID: "br-1", Table: 0, Priority: 100}
		change := NewFlowCreateChange(flow, "node-1")

		assert.Equal(t, EntityTypeFlow, change.EntityType)
		assert.Equal(t, OpTypeCreateFlow, change.Operation)
		assert.Equal(t, "flow-1", change.EntityID)
	})

	t.Run("NewFlowUpdateChange", func(t *testing.T) {
		flow := &FlowState{ID: "flow-1", BridgeID: "br-1", Table: 0, Priority: 100}
		change := NewFlowUpdateChange(flow, "node-1")

		assert.Equal(t, EntityTypeFlow, change.EntityType)
		assert.Equal(t, OpTypeUpdateFlow, change.Operation)
	})

	t.Run("NewFlowDeleteChange", func(t *testing.T) {
		change := NewFlowDeleteChange("br-1", "flow-1", "node-1")

		assert.Equal(t, EntityTypeFlow, change.EntityType)
		assert.Equal(t, OpTypeDeleteFlow, change.Operation)
		assert.Equal(t, "flow-1", change.EntityID)
		assert.Nil(t, change.Entity)
	})

	t.Run("NewVLANCreateChange", func(t *testing.T) {
		vlan := &VLANState{ID: 100, Name: "test-vlan"}
		change := NewVLANCreateChange(vlan, "node-1")

		assert.Equal(t, EntityTypeVLAN, change.EntityType)
		assert.Equal(t, OpTypeCreateVLAN, change.Operation)
		assert.Equal(t, "100", change.EntityID)
	})

	t.Run("NewVLANUpdateChange", func(t *testing.T) {
		vlan := &VLANState{ID: 100, Name: "test-vlan"}
		change := NewVLANUpdateChange(vlan, "node-1")

		assert.Equal(t, EntityTypeVLAN, change.EntityType)
		assert.Equal(t, OpTypeUpdateVLAN, change.Operation)
	})

	t.Run("NewVLANDeleteChange", func(t *testing.T) {
		change := NewVLANDeleteChange(100, "node-1")

		assert.Equal(t, EntityTypeVLAN, change.EntityType)
		assert.Equal(t, OpTypeDeleteVLAN, change.Operation)
		assert.Equal(t, "100", change.EntityID)
		assert.Nil(t, change.Entity)
	})
}

func TestOperationTypeExtraction(t *testing.T) {
	t.Run("ExtractCreateOperation", func(t *testing.T) {
		assert.Equal(t, OpTypeCreateBridge, ExtractCreateOperation(EntityTypeBridge))
		assert.Equal(t, OpTypeCreatePort, ExtractCreateOperation(EntityTypePort))
		assert.Equal(t, OpTypeCreateFlow, ExtractCreateOperation(EntityTypeFlow))
		assert.Equal(t, OpTypeCreateVLAN, ExtractCreateOperation(EntityTypeVLAN))
		assert.Equal(t, OperationType(""), ExtractCreateOperation(EntityType("unknown")))
	})

	t.Run("ExtractUpdateOperation", func(t *testing.T) {
		assert.Equal(t, OpTypeUpdateBridge, ExtractUpdateOperation(EntityTypeBridge))
		assert.Equal(t, OpTypeUpdatePort, ExtractUpdateOperation(EntityTypePort))
		assert.Equal(t, OpTypeUpdateFlow, ExtractUpdateOperation(EntityTypeFlow))
		assert.Equal(t, OpTypeUpdateVLAN, ExtractUpdateOperation(EntityTypeVLAN))
		assert.Equal(t, OperationType(""), ExtractUpdateOperation(EntityType("unknown")))
	})

	t.Run("ExtractDeleteOperation", func(t *testing.T) {
		assert.Equal(t, OpTypeDeleteBridge, ExtractDeleteOperation(EntityTypeBridge))
		assert.Equal(t, OpTypeDeletePort, ExtractDeleteOperation(EntityTypePort))
		assert.Equal(t, OpTypeDeleteFlow, ExtractDeleteOperation(EntityTypeFlow))
		assert.Equal(t, OpTypeDeleteVLAN, ExtractDeleteOperation(EntityTypeVLAN))
		assert.Equal(t, OperationType(""), ExtractDeleteOperation(EntityType("unknown")))
	})
}

func TestErrNotifierClosed(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrNotifierClosed{}
		assert.Equal(t, "state notifier is closed", err.Error())
	})

	t.Run("error type checking", func(t *testing.T) {
		var err error = ErrNotifierClosed{}
		var closedErr ErrNotifierClosed
		assert.True(t, errors.As(err, &closedErr))
	})
}

func TestQuicBaaSStateNotifier_Stats(t *testing.T) {
	t.Run("initial stats", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()
		defer notifier.Close()

		stats := notifier.Stats()
		assert.Equal(t, 0, stats.SubscriberCount)
		assert.Equal(t, uint64(0), stats.NotifyCount)
		assert.Equal(t, uint64(0), stats.DropCount)
		assert.False(t, stats.Closed)
	})

	t.Run("stats after operations", func(t *testing.T) {
		notifier := NewQuicBaaSStateNotifier()

		ch, unsub := notifier.Subscribe(NotificationFilter{})

		stats := notifier.Stats()
		assert.Equal(t, 1, stats.SubscriberCount)

		// Send some notifications.
		for i := 0; i < 5; i++ {
			change := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")
			notifier.Notify(change)
		}

		stats = notifier.Stats()
		assert.Equal(t, uint64(5), stats.NotifyCount)

		// Drain channel.
		for i := 0; i < 5; i++ {
			<-ch
		}

		unsub()
		time.Sleep(10 * time.Millisecond)

		stats = notifier.Stats()
		assert.Equal(t, 0, stats.SubscriberCount)

		notifier.Close()
		stats = notifier.Stats()
		assert.True(t, stats.Closed)
	})
}

func BenchmarkQuicBaaSStateNotifier_Notify(b *testing.B) {
	notifier := NewQuicBaaSStateNotifier()
	defer notifier.Close()

	ch, unsub := notifier.Subscribe(NotificationFilter{})
	defer unsub()

	// Drain notifications in background.
	go func() {
		for range ch {
		}
	}()

	change := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		notifier.Notify(change)
	}
}

func BenchmarkQuicBaaSStateNotifier_NotifyMultipleSubscribers(b *testing.B) {
	notifier := NewQuicBaaSStateNotifier()
	defer notifier.Close()

	// Create 10 subscribers.
	for i := 0; i < 10; i++ {
		ch, _ := notifier.Subscribe(NotificationFilter{})
		go func(c <-chan StateChange) {
			for range c {
			}
		}(ch)
	}

	change := NewBridgeCreateChange(&BridgeState{ID: "br-1", Name: "test"}, "node-1")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		notifier.Notify(change)
	}
}

func BenchmarkQuicBaaSStateNotifier_Subscribe(b *testing.B) {
	notifier := NewQuicBaaSStateNotifier()
	defer notifier.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, unsub := notifier.Subscribe(NotificationFilter{})
		unsub()
	}
}

func BenchmarkNotificationFilter_Matches(b *testing.B) {
	filter := NotificationFilter{
		EntityTypes: []EntityType{EntityTypeBridge, EntityTypePort},
		Operations:  []OperationType{OpTypeCreateBridge, OpTypeUpdateBridge},
	}

	change := StateChange{
		EntityType: EntityTypeBridge,
		Operation:  OpTypeCreateBridge,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		filter.Matches(change)
	}
}

// TestQuicBaaSStateNotifier_CloseExcludesSends is the regression test for the
// send-on-closed-channel panic fixed alongside it.
//
// unsubscribe closed a subscriber's channel while Notify could be sending to
// it: Notify checked sub.unsubscribed and then sent, with nothing ordering the
// check against the close, so the send could land after the close. The failure
// mode is a panic, not a lost notification, and a select with a default does
// not prevent it.
//
// The window is narrow, so each subtest drives the specific interleaving
// directly — senders are confirmed in flight before the close is triggered —
// and repeats it enough times to make the original defect fire reliably rather
// than relying on the broad concurrency tests above to stumble into it. A
// regression reappears as a panic that fails the package, under -race or not.
func TestQuicBaaSStateNotifier_CloseExcludesSends(t *testing.T) {
	change := NewBridgeCreateChange(&BridgeState{ID: "br-0", Name: "test"}, "node-1")

	// startSenders runs senders until the returned stop func is called, and
	// does not return until at least one Notify has completed, so the close
	// under test always races sends that are actually in flight.
	startSenders := func(n *QuicBaaSStateNotifier) (stop func()) {
		done := make(chan struct{})
		var wg sync.WaitGroup
		var sent atomic.Int64

		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					_ = n.Notify(change)
					sent.Add(1)
				}
			}()
		}

		for sent.Load() < 16 {
			runtime.Gosched()
		}

		return func() {
			close(done)
			wg.Wait()
		}
	}

	// drain keeps the subscriber's buffer free so Notify actually reaches the
	// send rather than taking the channel-full branch, which never touched the
	// closed channel and so never exposed the bug.
	drain := func(ch <-chan StateChange, done <-chan struct{}) *sync.WaitGroup {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case _, ok := <-ch:
					if !ok {
						return
					}
				case <-done:
					return
				}
			}
		}()
		return &wg
	}

	t.Run("unsubscribe while Notify is sending", func(t *testing.T) {
		for round := 0; round < 150; round++ {
			notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(1))
			ch, unsubscribe := notifier.Subscribe(NotificationFilter{})

			done := make(chan struct{})
			drained := drain(ch, done)

			stop := startSenders(notifier)
			unsubscribe() // closes ch while senders are mid-Notify
			stop()

			close(done)
			drained.Wait()
			require.NoError(t, notifier.Close())
		}
	})

	t.Run("Close while Notify is sending", func(t *testing.T) {
		for round := 0; round < 150; round++ {
			notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(1))
			ch, unsubscribe := notifier.Subscribe(NotificationFilter{})

			done := make(chan struct{})
			drained := drain(ch, done)

			stop := startSenders(notifier)
			require.NoError(t, notifier.Close()) // closes ch under in-flight sends
			stop()

			close(done)
			drained.Wait()
			unsubscribe() // must be safe after Close, and must not close twice
		}
	})

	t.Run("unsubscribe concurrent with Close", func(t *testing.T) {
		// Both paths closed the same channel, each guarded only by its own
		// atomic, so the two could close it twice: "close of closed channel".
		// This interleaving is narrower than the send/close one above — Close
		// must win the active CAS and unsubscribe must still win the slice CAS
		// — so it needs more rounds to fire reliably against the old code.
		for round := 0; round < 4000; round++ {
			notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(1))
			_, unsubscribe := notifier.Subscribe(NotificationFilter{})

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				unsubscribe()
			}()
			go func() {
				defer wg.Done()
				_ = notifier.Close()
			}()
			wg.Wait()
		}
	})
}

// TestQuicBaaSStateNotifier_SubscribeRacingClose asserts the shutdown contract
// Close documents: once Close has returned, every channel Subscribe handed out
// is closed. A consumer ranging over its channel relies on that close to
// terminate, so a subscriber published after Close finished would block its
// consumer forever on a channel that can never receive anything — Notify
// returns early on a closed notifier.
//
// Subscribe checked n.closed once, before building the subscriber and entering
// the CAS loop, so a Subscribe that passed the check could still publish itself
// after a concurrent Close had iterated the subscriber slice and returned.
func TestQuicBaaSStateNotifier_SubscribeRacingClose(t *testing.T) {
	// The window is between Subscribe's closed check and its CAS — nanoseconds
	// wide — so the two calls are released from a start barrier to make them
	// genuinely overlap rather than relying on goroutine start order.
	for round := 0; round < 1500; round++ {
		notifier := NewQuicBaaSStateNotifier(WithNotifierBufferSize(1))

		var ch <-chan StateChange
		start := make(chan struct{})
		var ready, wg sync.WaitGroup
		ready.Add(2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			ch, _ = notifier.Subscribe(NotificationFilter{})
		}()
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			_ = notifier.Close()
		}()
		ready.Wait()
		close(start)
		wg.Wait()

		// Both calls have returned, so the channel must be closed either by
		// Close itself or by Subscribe observing the shutdown.
		select {
		case _, ok := <-ch:
			require.False(t, ok, "round %d: channel delivered a value after Close", round)
		default:
			t.Fatalf("round %d: Subscribe returned an open channel that Close never closed", round)
		}
	}
}
