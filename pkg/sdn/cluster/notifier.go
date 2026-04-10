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
	"fmt"
	"sync/atomic"
	"time"
)

// EntityType identifies the type of entity in a state change notification.
type EntityType string

const (
	// EntityTypeBridge represents a bridge entity.
	EntityTypeBridge EntityType = "bridge"

	// EntityTypePort represents a port entity.
	EntityTypePort EntityType = "port"

	// EntityTypeFlow represents a flow entity.
	EntityTypeFlow EntityType = "flow"

	// EntityTypeVLAN represents a VLAN entity.
	EntityTypeVLAN EntityType = "vlan"
)

// defaultSubscriberBufferSize is the default channel buffer size for subscribers.
const defaultSubscriberBufferSize = 256

// defaultMaxDroppedNotifications is the threshold for logging slow consumer warnings.
const defaultMaxDroppedNotifications = 100

// StateChange represents a notification about a state change in the cluster.
type StateChange struct {
	// EntityType identifies the type of entity that changed.
	EntityType EntityType

	// Operation identifies what operation was performed.
	Operation OperationType

	// EntityID is the unique identifier of the entity.
	EntityID string

	// Entity contains the entity data. The concrete type depends on EntityType:
	//   - EntityTypeBridge: *BridgeState
	//   - EntityTypePort: *PortState
	//   - EntityTypeFlow: *FlowState
	//   - EntityTypeVLAN: *VLANState
	Entity interface{}

	// Timestamp is when the change occurred.
	Timestamp time.Time

	// NodeID identifies the cluster node where the change originated.
	NodeID string
}

// NotificationFilter specifies which notifications a subscriber wants to receive.
// An empty slice means match all values for that field.
type NotificationFilter struct {
	// EntityTypes filters by entity type. Empty means all types.
	EntityTypes []EntityType

	// Operations filters by operation type. Empty means all operations.
	Operations []OperationType
}

// Matches returns true if the state change matches this filter.
func (f NotificationFilter) Matches(change StateChange) bool {
	if len(f.EntityTypes) > 0 {
		found := false
		for _, et := range f.EntityTypes {
			if et == change.EntityType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(f.Operations) > 0 {
		found := false
		for _, op := range f.Operations {
			if op == change.Operation {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// StateNotifier broadcasts state change notifications to subscribers.
// It implements a pub/sub pattern with filtering support.
type StateNotifier interface {
	// Subscribe creates a new subscription with the given filter.
	// Returns a channel for receiving notifications and an unsubscribe function.
	// The unsubscribe function MUST be called when the subscription is no longer needed.
	Subscribe(filter NotificationFilter) (<-chan StateChange, func())

	// Notify broadcasts a state change to all matching subscribers.
	// Returns an error if the notifier is closed.
	Notify(change StateChange) error

	// Close shuts down the notifier and closes all subscriber channels.
	Close() error
}

// subscriber represents an active subscription.
// All fields after id and channel are accessed atomically to avoid races.
type subscriber struct {
	id            uint64
	filter        NotificationFilter
	channel       chan StateChange
	slowThreshold int

	// These fields are accessed atomically.
	dropped      atomic.Uint64
	active       atomic.Bool
	unsubscribed atomic.Bool
	lastDropWarn atomic.Int64
}

// QuicBaaSStateNotifier implements StateNotifier using lock-free algorithms.
// It uses atomic operations for subscriber management and non-blocking sends
// to handle slow consumers without blocking the notification path.
type QuicBaaSStateNotifier struct {
	// subscribers is the slice of pointers to active subscribers.
	// We use atomic operations to manage additions/removals.
	// Using pointers ensures atomic fields in subscribers are not copied.
	subscribers atomic.Pointer[[]*subscriber]

	// nextID is used to generate unique subscriber IDs.
	nextID atomic.Uint64

	// closed indicates whether the notifier has been shut down.
	closed atomic.Bool

	// bufferSize is the channel buffer size for new subscribers.
	bufferSize int

	// notifyCount tracks the total number of notifications sent.
	notifyCount atomic.Uint64

	// dropCount tracks the total number of dropped notifications.
	dropCount atomic.Uint64
}

// StateNotifierOption is a functional option for configuring QuicBaaSStateNotifier.
type StateNotifierOption func(*stateNotifierConfig)

type stateNotifierConfig struct {
	bufferSize    int
	slowThreshold int
}

// WithNotifierBufferSize sets the channel buffer size for subscribers.
func WithNotifierBufferSize(size int) StateNotifierOption {
	return func(c *stateNotifierConfig) {
		if size > 0 {
			c.bufferSize = size
		}
	}
}

// WithSlowConsumerThreshold sets the number of dropped notifications
// before logging a warning for slow consumers.
func WithSlowConsumerThreshold(threshold int) StateNotifierOption {
	return func(c *stateNotifierConfig) {
		if threshold > 0 {
			c.slowThreshold = threshold
		}
	}
}

// NewQuicBaaSStateNotifier creates a new QuicBaaSStateNotifier instance.
func NewQuicBaaSStateNotifier(opts ...StateNotifierOption) *QuicBaaSStateNotifier {
	cfg := &stateNotifierConfig{
		bufferSize:    defaultSubscriberBufferSize,
		slowThreshold: defaultMaxDroppedNotifications,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	n := &QuicBaaSStateNotifier{
		bufferSize: cfg.bufferSize,
	}

	// Initialize with empty subscriber slice.
	emptySlice := make([]*subscriber, 0)
	n.subscribers.Store(&emptySlice)

	return n
}

// Subscribe creates a new subscription with the given filter.
// The returned channel receives state changes matching the filter.
// The unsubscribe function MUST be called to clean up resources.
func (n *QuicBaaSStateNotifier) Subscribe(filter NotificationFilter) (<-chan StateChange, func()) {
	if n.closed.Load() {
		// Return a closed channel if the notifier is closed.
		ch := make(chan StateChange)
		close(ch)
		return ch, func() {}
	}

	// Generate unique subscriber ID.
	id := n.nextID.Add(1)

	// Create subscriber with buffered channel.
	sub := &subscriber{
		id:            id,
		filter:        filter,
		channel:       make(chan StateChange, n.bufferSize),
		slowThreshold: defaultMaxDroppedNotifications,
	}
	sub.active.Store(true)

	// Add subscriber using lock-free compare-and-swap loop.
	for {
		oldSubs := n.subscribers.Load()
		newSubs := make([]*subscriber, len(*oldSubs)+1)
		copy(newSubs, *oldSubs)
		newSubs[len(*oldSubs)] = sub

		if n.subscribers.CompareAndSwap(oldSubs, &newSubs) {
			break
		}
		// CAS failed, retry.
	}

	// Create unsubscribe function.
	unsubscribe := func() {
		n.unsubscribe(id)
	}

	return sub.channel, unsubscribe
}

// unsubscribe removes a subscriber by ID.
func (n *QuicBaaSStateNotifier) unsubscribe(id uint64) {
	for {
		oldSubs := n.subscribers.Load()
		if oldSubs == nil || len(*oldSubs) == 0 {
			return
		}

		// Find the subscriber to remove.
		var targetIndex = -1
		var targetSub *subscriber
		for i, sub := range *oldSubs {
			if sub.id == id {
				targetIndex = i
				targetSub = sub
				break
			}
		}

		if targetIndex == -1 {
			// Subscriber not found, already removed.
			return
		}

		// Mark as unsubscribed to prevent further sends.
		// This is safe because we're operating on a pointer, not a copy.
		targetSub.unsubscribed.Store(true)
		targetSub.active.Store(false)

		// Create new slice without this subscriber.
		newSubs := make([]*subscriber, 0, len(*oldSubs)-1)
		for i, sub := range *oldSubs {
			if i != targetIndex {
				newSubs = append(newSubs, sub)
			}
		}

		if n.subscribers.CompareAndSwap(oldSubs, &newSubs) {
			// Close the channel after successful removal.
			close(targetSub.channel)
			return
		}
		// CAS failed, retry.
	}
}

// Notify broadcasts a state change to all matching subscribers.
// Uses non-blocking sends to prevent slow consumers from blocking.
func (n *QuicBaaSStateNotifier) Notify(change StateChange) error {
	if n.closed.Load() {
		return ErrNotifierClosed{}
	}

	n.notifyCount.Add(1)

	subs := n.subscribers.Load()
	if subs == nil {
		return nil
	}

	for _, sub := range *subs {
		// Skip inactive or unsubscribed subscribers.
		if !sub.active.Load() || sub.unsubscribed.Load() {
			continue
		}

		// Check if this notification matches the subscriber's filter.
		if !sub.filter.Matches(change) {
			continue
		}

		// Non-blocking send to prevent slow consumers from blocking.
		select {
		case sub.channel <- change:
			// Successfully sent.
		default:
			// Channel full, drop notification for this subscriber.
			dropped := sub.dropped.Add(1)
			n.dropCount.Add(1)

			// Rate-limited slow consumer warning.
			if dropped%uint64(sub.slowThreshold) == 0 {
				now := time.Now().Unix()
				lastWarn := sub.lastDropWarn.Load()
				// Only warn once per minute per subscriber.
				if now-lastWarn >= 60 {
					sub.lastDropWarn.Store(now)
				}
			}
		}
	}

	return nil
}

// Close shuts down the notifier and closes all subscriber channels.
func (n *QuicBaaSStateNotifier) Close() error {
	if !n.closed.CompareAndSwap(false, true) {
		return ErrNotifierClosed{}
	}

	// Get all subscribers and close their channels.
	subs := n.subscribers.Load()
	if subs != nil {
		for _, sub := range *subs {
			if sub.active.CompareAndSwap(true, false) {
				close(sub.channel)
			}
		}
	}

	// Clear subscribers.
	emptySlice := make([]*subscriber, 0)
	n.subscribers.Store(&emptySlice)

	return nil
}

// Stats returns statistics about the notifier's operation.
func (n *QuicBaaSStateNotifier) Stats() NotifierStats {
	subs := n.subscribers.Load()
	subscriberCount := 0
	if subs != nil {
		subscriberCount = len(*subs)
	}

	return NotifierStats{
		SubscriberCount: subscriberCount,
		NotifyCount:     n.notifyCount.Load(),
		DropCount:       n.dropCount.Load(),
		Closed:          n.closed.Load(),
	}
}

// NotifierStats contains statistics about the notifier's operation.
type NotifierStats struct {
	// SubscriberCount is the current number of active subscribers.
	SubscriberCount int

	// NotifyCount is the total number of notifications sent.
	NotifyCount uint64

	// DropCount is the total number of dropped notifications due to slow consumers.
	DropCount uint64

	// Closed indicates whether the notifier has been shut down.
	Closed bool
}

// ErrNotifierClosed is returned when operations are attempted on a closed notifier.
type ErrNotifierClosed struct{}

func (e ErrNotifierClosed) Error() string {
	return "state notifier is closed"
}

// ExtractCreateOperation extracts the create operation type from an entity type.
func ExtractCreateOperation(entityType EntityType) OperationType {
	switch entityType {
	case EntityTypeBridge:
		return OpTypeCreateBridge
	case EntityTypePort:
		return OpTypeCreatePort
	case EntityTypeFlow:
		return OpTypeCreateFlow
	case EntityTypeVLAN:
		return OpTypeCreateVLAN
	default:
		return ""
	}
}

// ExtractUpdateOperation extracts the update operation type from an entity type.
func ExtractUpdateOperation(entityType EntityType) OperationType {
	switch entityType {
	case EntityTypeBridge:
		return OpTypeUpdateBridge
	case EntityTypePort:
		return OpTypeUpdatePort
	case EntityTypeFlow:
		return OpTypeUpdateFlow
	case EntityTypeVLAN:
		return OpTypeUpdateVLAN
	default:
		return ""
	}
}

// ExtractDeleteOperation extracts the delete operation type from an entity type.
func ExtractDeleteOperation(entityType EntityType) OperationType {
	switch entityType {
	case EntityTypeBridge:
		return OpTypeDeleteBridge
	case EntityTypePort:
		return OpTypeDeletePort
	case EntityTypeFlow:
		return OpTypeDeleteFlow
	case EntityTypeVLAN:
		return OpTypeDeleteVLAN
	default:
		return ""
	}
}

// NewBridgeCreateChange creates a StateChange for bridge creation.
func NewBridgeCreateChange(bridge *BridgeState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeBridge,
		Operation:  OpTypeCreateBridge,
		EntityID:   bridge.ID,
		Entity:     bridge,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewBridgeUpdateChange creates a StateChange for bridge update.
func NewBridgeUpdateChange(bridge *BridgeState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeBridge,
		Operation:  OpTypeUpdateBridge,
		EntityID:   bridge.ID,
		Entity:     bridge,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewBridgeDeleteChange creates a StateChange for bridge deletion.
func NewBridgeDeleteChange(bridgeID string, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeBridge,
		Operation:  OpTypeDeleteBridge,
		EntityID:   bridgeID,
		Entity:     nil,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewPortCreateChange creates a StateChange for port creation.
func NewPortCreateChange(port *PortState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypePort,
		Operation:  OpTypeCreatePort,
		EntityID:   port.ID,
		Entity:     port,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewPortUpdateChange creates a StateChange for port update.
func NewPortUpdateChange(port *PortState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypePort,
		Operation:  OpTypeUpdatePort,
		EntityID:   port.ID,
		Entity:     port,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewPortDeleteChange creates a StateChange for port deletion.
func NewPortDeleteChange(portID string, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypePort,
		Operation:  OpTypeDeletePort,
		EntityID:   portID,
		Entity:     nil,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewFlowCreateChange creates a StateChange for flow creation.
func NewFlowCreateChange(flow *FlowState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeFlow,
		Operation:  OpTypeCreateFlow,
		EntityID:   flow.ID,
		Entity:     flow,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewFlowUpdateChange creates a StateChange for flow update.
func NewFlowUpdateChange(flow *FlowState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeFlow,
		Operation:  OpTypeUpdateFlow,
		EntityID:   flow.ID,
		Entity:     flow,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewFlowDeleteChange creates a StateChange for flow deletion.
func NewFlowDeleteChange(bridgeID, flowID string, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeFlow,
		Operation:  OpTypeDeleteFlow,
		EntityID:   flowID,
		Entity:     nil,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewVLANCreateChange creates a StateChange for VLAN creation.
func NewVLANCreateChange(vlan *VLANState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeVLAN,
		Operation:  OpTypeCreateVLAN,
		EntityID:   fmt.Sprintf("%d", vlan.ID),
		Entity:     vlan,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewVLANUpdateChange creates a StateChange for VLAN update.
func NewVLANUpdateChange(vlan *VLANState, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeVLAN,
		Operation:  OpTypeUpdateVLAN,
		EntityID:   fmt.Sprintf("%d", vlan.ID),
		Entity:     vlan,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// NewVLANDeleteChange creates a StateChange for VLAN deletion.
func NewVLANDeleteChange(vlanID uint16, nodeID string) StateChange {
	return StateChange{
		EntityType: EntityTypeVLAN,
		Operation:  OpTypeDeleteVLAN,
		EntityID:   fmt.Sprintf("%d", vlanID),
		Entity:     nil,
		Timestamp:  time.Now(),
		NodeID:     nodeID,
	}
}

// Ensure QuicBaaSStateNotifier implements StateNotifier.
var _ StateNotifier = (*QuicBaaSStateNotifier)(nil)
