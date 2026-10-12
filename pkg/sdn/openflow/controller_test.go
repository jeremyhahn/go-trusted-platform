package openflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketInControllerDispatchesExactKey(t *testing.T) {
	source := newPacketSource()
	handled := make(chan PacketIn, 1)
	controller := startController(t, source, PacketInRoute{
		Key: PacketInKey{Reason: PacketInReasonAction, Cookie: 0xf5},
		Handler: func(_ context.Context, packet PacketIn) error {
			handled <- packet
			return nil
		},
	})

	// Only the exact cookie reaches the handler; a cookie sharing its
	// high bits does not.
	source.emit(PacketIn{Reason: PacketInReasonAction, Cookie: 0xf0})
	source.emit(PacketIn{Reason: PacketInReasonAction, Cookie: 0xf5})

	select {
	case got := <-handled:
		assert.Equal(t, uint64(0xf5), got.Cookie)
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called")
	}
	require.Eventually(t, func() bool { return controller.Unhandled() == 1 }, 5*time.Second, time.Millisecond)
	assert.Zero(t, controller.Failed())
}

func TestPacketInControllerCountsUnhandledAndFailedSeparately(t *testing.T) {
	source := newPacketSource()
	controller := startController(t, source, PacketInRoute{
		Key: PacketInKey{Reason: PacketInReasonAction, Cookie: 0xf5},
		Handler: func(_ context.Context, _ PacketIn) error {
			return errors.New("handler failed")
		},
	})

	source.emit(PacketIn{Reason: PacketInReasonNoMatch, Cookie: 0xf5})
	source.emit(PacketIn{Reason: PacketInReasonAction, Cookie: 0xf5})

	require.Eventually(t, func() bool {
		return controller.Unhandled() == 1 && controller.Failed() == 1
	}, 5*time.Second, time.Millisecond)
}

func TestNewPacketInControllerRejectsInvalidConfig(t *testing.T) {
	key := PacketInKey{Reason: PacketInReasonAction, Cookie: 1}
	tests := []struct {
		name  string
		cfg   PacketInControllerConfig
		field string
	}{
		{
			name:  "nil source",
			cfg:   PacketInControllerConfig{Queue: 1, Workers: 1},
			field: "source",
		},
		{
			name:  "no workers",
			cfg:   PacketInControllerConfig{Source: newPacketSource(), Queue: 1},
			field: "workers",
		},
		{
			name:  "zero queue",
			cfg:   PacketInControllerConfig{Source: newPacketSource(), Workers: 1},
			field: "queue",
		},
		{
			name: "nil handler",
			cfg: PacketInControllerConfig{Source: newPacketSource(), Queue: 1, Workers: 1,
				Routes: []PacketInRoute{{Key: key}}},
			field: "route handler",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPacketInController(tt.cfg)
			var invalid *ErrInvalidPacketInConfig
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, tt.field, invalid.Field)
			assert.NotErrorIs(t, err, ErrNotConnected)
		})
	}
}

func TestNewPacketInControllerRejectsOverlappingRoutes(t *testing.T) {
	handler := func(context.Context, PacketIn) error { return nil }
	key := PacketInKey{Reason: PacketInReasonAction, Cookie: 0xf5}
	source := newPacketSource()

	_, err := NewPacketInController(PacketInControllerConfig{
		Source:  source,
		Queue:   1,
		Workers: 1,
		Routes:  []PacketInRoute{{Key: key, Handler: handler}, {Key: key, Handler: handler}},
	})

	var duplicate *ErrDuplicatePacketInRoute
	require.True(t, errors.As(err, &duplicate), "got %v", err)
	assert.Equal(t, key, duplicate.Key)
	assert.Empty(t, source.subscriptions, "a rejected config must not subscribe")
}

func TestPacketInSubscriptionCountsQueueDrops(t *testing.T) {
	subscription, err := NewPacketInSubscription(1, nil)
	require.NoError(t, err)

	assert.True(t, subscription.Deliver(PacketIn{Cookie: 1}))
	assert.False(t, subscription.Deliver(PacketIn{Cookie: 2}), "a full queue drops")
	assert.Equal(t, uint64(1), subscription.Dropped())
	assert.Equal(t, uint64(1), (<-subscription.C()).Cookie)
}

func TestPacketInSubscriptionCancelStopsDelivery(t *testing.T) {
	released := 0
	subscription, err := NewPacketInSubscription(1, func() { released++ })
	require.NoError(t, err)

	subscription.Cancel()
	subscription.Cancel()

	assert.Equal(t, 1, released)
	assert.False(t, subscription.Deliver(PacketIn{}), "a cancelled subscription accepts nothing")
	_, open := <-subscription.C()
	assert.False(t, open)
	assert.Zero(t, subscription.Dropped(), "refusing after cancel is not a queue drop")
}

func TestNewPacketInSubscriptionRejectsBadQueue(t *testing.T) {
	_, err := NewPacketInSubscription(0, nil)
	var invalid *ErrInvalidPacketInConfig
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "queue", invalid.Field)
}

func startController(t *testing.T, source *packetSource, routes ...PacketInRoute) *PacketInController {
	t.Helper()
	controller, err := NewPacketInController(PacketInControllerConfig{
		Source:  source,
		Queue:   4,
		Workers: 1,
		Routes:  routes,
	})
	require.NoError(t, err)
	require.NoError(t, controller.Start(context.Background()))
	t.Cleanup(controller.Stop)
	return controller
}

type packetSource struct {
	subscriptions []*PacketInSubscription
}

func newPacketSource() *packetSource {
	return &packetSource{}
}

func (s *packetSource) SubscribePacketIn(queueSize int) (*PacketInSubscription, error) {
	subscription, err := NewPacketInSubscription(queueSize, nil)
	if err != nil {
		return nil, err
	}
	s.subscriptions = append(s.subscriptions, subscription)
	return subscription, nil
}

func (s *packetSource) emit(packet PacketIn) {
	for _, subscription := range s.subscriptions {
		subscription.Deliver(packet)
	}
}
