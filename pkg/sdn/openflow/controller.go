package openflow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// PacketInSource provides packet-in subscriptions.
type PacketInSource interface {
	SubscribePacketIn(queueSize int) (*PacketInSubscription, error)
}

// PacketOutSender emits packet-outs.
type PacketOutSender interface {
	SendPacketOut(ctx context.Context, packet *PacketOut) error
}

// PacketInSubscription is one bounded packet-in queue. The switch reader
// delivers into it without blocking: a full queue drops the packet and
// counts the drop, so a slow consumer never stalls the OpenFlow connection.
type PacketInSubscription struct {
	queue   chan PacketIn
	release func()

	mu      sync.RWMutex
	closed  bool
	once    sync.Once
	dropped atomic.Uint64
}

// NewPacketInSubscription creates a subscription holding up to queueSize
// packets. release, when set, runs once on Cancel so the source can stop
// delivering to it.
func NewPacketInSubscription(queueSize int, release func()) (*PacketInSubscription, error) {
	if queueSize <= 0 {
		return nil, &ErrInvalidPacketInConfig{Field: "queue", Reason: "must be positive"}
	}
	return &PacketInSubscription{queue: make(chan PacketIn, queueSize), release: release}, nil
}

// C returns the queue. It is closed by Cancel.
func (s *PacketInSubscription) C() <-chan PacketIn {
	return s.queue
}

// Deliver enqueues packet without blocking. It returns false, counting a
// drop, when the queue is full; a cancelled subscription accepts nothing.
func (s *PacketInSubscription) Deliver(packet PacketIn) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false
	}
	select {
	case s.queue <- packet:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

// Dropped returns the packets discarded because the queue was full.
func (s *PacketInSubscription) Dropped() uint64 {
	return s.dropped.Load()
}

// Cancel unregisters the subscription from its source and closes the
// queue. It is safe to call more than once.
func (s *PacketInSubscription) Cancel() {
	s.once.Do(func() {
		// Release before taking the lock: the source holds its own lock
		// while delivering, so taking them in the other order could
		// deadlock against a concurrent Deliver.
		if s.release != nil {
			s.release()
		}
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
	})
}

// PacketInHandler handles one packet-in.
type PacketInHandler func(context.Context, PacketIn) error

// PacketInKey selects a handler by the exact packet-in reason and the
// cookie of the flow entry that produced it.
type PacketInKey struct {
	Reason uint8
	Cookie uint64
}

// PacketInRoute binds a handler to one packet-in key.
type PacketInRoute struct {
	Key     PacketInKey
	Handler PacketInHandler
}

// PacketInControllerConfig configures a packet-in controller.
type PacketInControllerConfig struct {
	Source  PacketInSource
	Queue   int
	Workers int
	Routes  []PacketInRoute
}

// PacketInController dispatches switch packet-ins through a bounded queue
// to the handler registered for their exact (reason, cookie).
type PacketInController struct {
	subscription *PacketInSubscription
	workers      int
	handlers     map[PacketInKey]PacketInHandler

	ctx    context.Context
	stop   context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	closed atomic.Bool

	unhandled atomic.Uint64
	failed    atomic.Uint64
}

// NewPacketInController validates cfg, rejecting overlapping routes, and
// subscribes to the source.
func NewPacketInController(cfg PacketInControllerConfig) (*PacketInController, error) {
	if cfg.Source == nil {
		return nil, &ErrInvalidPacketInConfig{Field: "source", Reason: "is nil"}
	}
	if cfg.Workers <= 0 {
		return nil, &ErrInvalidPacketInConfig{Field: "workers", Reason: "must be positive"}
	}
	handlers := make(map[PacketInKey]PacketInHandler, len(cfg.Routes))
	for _, route := range cfg.Routes {
		if route.Handler == nil {
			return nil, &ErrInvalidPacketInConfig{Field: "route handler", Reason: "is nil"}
		}
		if _, exists := handlers[route.Key]; exists {
			return nil, &ErrDuplicatePacketInRoute{Key: route.Key}
		}
		handlers[route.Key] = route.Handler
	}
	subscription, err := cfg.Source.SubscribePacketIn(cfg.Queue)
	if err != nil {
		return nil, err
	}
	return &PacketInController{
		subscription: subscription,
		workers:      cfg.Workers,
		handlers:     handlers,
	}, nil
}

// Start begins packet-in dispatch.
func (c *PacketInController) Start(parent context.Context) error {
	if c.closed.Load() {
		return ErrConnectionClosed
	}
	c.ctx, c.stop = context.WithCancel(parent)
	for i := 0; i < c.workers; i++ {
		c.wg.Add(1)
		go c.run()
	}
	return nil
}

func (c *PacketInController) run() {
	defer c.wg.Done()
	queue := c.subscription.C()
	for {
		select {
		case <-c.ctx.Done():
			return
		case packet, ok := <-queue:
			if !ok {
				return
			}
			handler, ok := c.handlers[PacketInKey{Reason: packet.Reason, Cookie: packet.Cookie}]
			if !ok {
				c.unhandled.Add(1)
				continue
			}
			if err := handler(c.ctx, packet); err != nil && !errors.Is(err, context.Canceled) {
				c.failed.Add(1)
			}
		}
	}
}

// Stop shuts down workers and unsubscribes from packet-ins.
func (c *PacketInController) Stop() {
	c.once.Do(func() {
		c.closed.Store(true)
		if c.stop != nil {
			c.stop()
		}
		c.subscription.Cancel()
		c.wg.Wait()
	})
}

// Unhandled returns packet-ins no route matched.
func (c *PacketInController) Unhandled() uint64 {
	return c.unhandled.Load()
}

// Failed returns packet-ins whose handler returned an error.
func (c *PacketInController) Failed() uint64 {
	return c.failed.Load()
}

// QueueDropped returns packet-ins discarded because the queue was full.
func (c *PacketInController) QueueDropped() uint64 {
	return c.subscription.Dropped()
}
