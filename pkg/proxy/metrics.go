package proxy

import "sync/atomic"

// routeMetrics holds the lock-free per-route counters incremented on the hot
// path. The zero value is ready to use.
type routeMetrics struct {
	requests atomic.Uint64
	denied   atomic.Uint64
	errors   atomic.Uint64
	bytesOut atomic.Uint64
}

// RouteMetrics is a point-in-time snapshot of one route's counters.
type RouteMetrics struct {
	Requests uint64
	Denied   uint64
	Errors   uint64
	BytesOut uint64
}

// MetricsSnapshot is a point-in-time snapshot of all engine counters.
type MetricsSnapshot struct {
	// NotFound counts requests that matched no route.
	NotFound uint64
	// Routes maps route ID to its counters.
	Routes map[string]RouteMetrics
}

// Metrics returns a consistent snapshot of the engine counters. Counters for
// route IDs that survive a Reload are carried over.
func (e *Engine) Metrics() MetricsSnapshot {
	st := e.state.Load()
	snap := MetricsSnapshot{
		NotFound: e.notFound.Load(),
		Routes:   make(map[string]RouteMetrics, len(st.metrics)),
	}
	for id, m := range st.metrics {
		snap.Routes[id] = RouteMetrics{
			Requests: m.requests.Load(),
			Denied:   m.denied.Load(),
			Errors:   m.errors.Load(),
			BytesOut: m.bytesOut.Load(),
		}
	}
	return snap
}
