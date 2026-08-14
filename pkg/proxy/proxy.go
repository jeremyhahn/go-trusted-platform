// Package proxy implements a high-performance authenticating reverse-proxy
// engine: lock-free routing, pooled per-pool transports, shared per-route
// reverse proxies (httputil.ReverseProxy with the Rewrite API), hot reload
// with transport carryover, and audit/metrics plumbing. The
// trusted-computing authentication chain is injected behind the AuthChain
// interface; the engine is fail-closed and refuses to compose without it
// whenever any route requires authentication.
package proxy

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// compiledState is the immutable compiled configuration published through an
// atomic pointer so the request hot path never takes a lock.
type compiledState struct {
	cfg     Config
	table   *routeTable
	pools   map[string]*compiledPool
	metrics map[string]*routeMetrics
}

// Engine is the reverse-proxy engine. Create it with New, run it with Start,
// swap configuration with Reload, and shut it down with Stop. The Engine is
// itself the shared http.Handler served by every listener.
type Engine struct {
	deps      Deps
	state     atomic.Pointer[compiledState]
	notFound  atomic.Uint64
	reloads   atomic.Uint64
	started   atomic.Bool
	mu        sync.Mutex // guards control-plane state: listeners, Start/Stop/Reload orchestration
	listeners []*listenerRuntime
	wg        sync.WaitGroup
}

// Status reports the engine's compiled configuration and listener state.
type Status struct {
	Routes      int
	Pools       int
	Listeners   []ListenerStatus
	ReloadCount uint64
}

// New validates and compiles the configuration and returns a ready Engine.
// Composition is fail-closed: any non-public route requires deps.Auth and
// deps.ServerTLS, and any pool with a TLS trust class requires deps.Trust.
func New(cfg Config, deps Deps) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	deps = deps.withDefaults()
	if err := checkFailClosed(&cfg, deps); err != nil {
		return nil, err
	}
	st, retired, err := compile(&cfg, deps, nil)
	if err != nil {
		return nil, err
	}
	closeRetired(retired)
	e := &Engine{deps: deps}
	e.state.Store(st)
	return e, nil
}

// Reload validates and compiles the new configuration, then atomically swaps
// it in. Pools whose ID and configuration are unchanged carry their pooled
// transport (and warm connections) into the new state; transports of changed
// or removed pools have their idle connections closed after the swap. On any
// validation or compile error the running state is untouched. Listener
// changes take effect on the next Start; running listeners are not restarted.
func (e *Engine) Reload(cfg Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkFailClosed(&cfg, e.deps); err != nil {
		return err
	}
	st, retired, err := compile(&cfg, e.deps, e.state.Load())
	if err != nil {
		return err
	}
	e.state.Store(st)
	closeRetired(retired)
	e.reloads.Add(1)
	return nil
}

// Status returns the engine status including per-listener bound addresses
// when started.
func (e *Engine) Status() *Status {
	st := e.state.Load()
	e.mu.Lock()
	bound := make(map[string]string, len(e.listeners))
	for _, rt := range e.listeners {
		bound[rt.cfg.ID] = rt.ln.Addr().String()
	}
	e.mu.Unlock()
	status := &Status{
		Routes:      len(st.cfg.Routes),
		Pools:       len(st.cfg.Pools),
		Listeners:   make([]ListenerStatus, 0, len(st.cfg.Listeners)),
		ReloadCount: e.reloads.Load(),
	}
	for i := range st.cfg.Listeners {
		lc := st.cfg.Listeners[i]
		status.Listeners = append(status.Listeners, ListenerStatus{
			ID:           lc.ID,
			Address:      lc.Address,
			BoundAddress: bound[lc.ID],
			TLS:          e.deps.ServerTLS != nil,
		})
	}
	return status
}

// compile builds the immutable compiled state from a validated
// configuration. prev (which may be nil) supplies pools for transport
// carryover and metrics for counter continuity across reloads.
func compile(cfg *Config, deps Deps, prev *compiledState) (*compiledState, []*http.Transport, error) {
	var prevPools map[string]*compiledPool
	var prevMetrics map[string]*routeMetrics
	if prev != nil {
		prevPools = prev.pools
		prevMetrics = prev.metrics
	}
	pools, retired, err := compilePools(cfg, deps, prevPools)
	if err != nil {
		return nil, nil, err
	}
	metrics := make(map[string]*routeMetrics, len(cfg.Routes))
	compiled := make([]*CompiledRoute, 0, len(cfg.Routes))
	for i := range cfg.Routes {
		rc := cfg.Routes[i]
		mergeAuthDefaults(&rc.Auth, cfg.Defaults)
		m := prevMetrics[rc.ID]
		if m == nil {
			m = &routeMetrics{}
		}
		metrics[rc.ID] = m
		cr := &CompiledRoute{cfg: rc, pool: pools[rc.PoolID], metrics: m}
		cr.rp = newReverseProxy(&cr.cfg, cr.pool, m, deps)
		compiled = append(compiled, cr)
	}
	st := &compiledState{
		cfg:     *cfg,
		table:   buildRouteTable(compiled),
		pools:   pools,
		metrics: metrics,
	}
	return st, retired, nil
}

// mergeAuthDefaults fills optional per-route auth fields from the configured
// defaults.
func mergeAuthDefaults(a *AuthRequirements, d AuthDefaults) {
	if a.RequireAttestation && a.AttestationMaxAge <= 0 {
		a.AttestationMaxAge = d.AttestationMaxAge
	}
	if a.BackendZone == "" {
		a.BackendZone = d.BackendZone
	}
}

func closeRetired(retired []*http.Transport) {
	for _, tr := range retired {
		tr.CloseIdleConnections()
	}
}
