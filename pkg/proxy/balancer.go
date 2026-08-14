package proxy

import "sync/atomic"

// BalancerRoundRobin is the registered name of the round-robin balancer and
// the default when a pool leaves Balancer empty.
const BalancerRoundRobin = "round-robin"

// Balancer selects the next backend for a request. Implementations must be
// safe for concurrent use.
type Balancer interface {
	Next(backends []*backend) *backend
}

// balancerFactory constructs a fresh Balancer instance for one pool.
type balancerFactory func() Balancer

// balancerRegistry dispatches balancer names to factories.
var balancerRegistry = map[string]balancerFactory{
	BalancerRoundRobin: newRoundRobin,
}

// newBalancer returns a new Balancer instance for the given registered name.
// An empty name selects round-robin. Unknown names return ErrUnknownBalancer.
func newBalancer(name string) (Balancer, error) {
	if name == "" {
		name = BalancerRoundRobin
	}
	factory, ok := balancerRegistry[name]
	if !ok {
		return nil, ErrUnknownBalancer
	}
	return factory(), nil
}

// roundRobin cycles through backends with a lock-free atomic counter.
type roundRobin struct {
	counter atomic.Uint64
}

func newRoundRobin() Balancer { return &roundRobin{} }

// Next implements Balancer. It returns nil for an empty backend list.
func (rr *roundRobin) Next(backends []*backend) *backend {
	if len(backends) == 0 {
		return nil
	}
	n := rr.counter.Add(1) - 1
	return backends[n%uint64(len(backends))]
}

var _ Balancer = (*roundRobin)(nil)
