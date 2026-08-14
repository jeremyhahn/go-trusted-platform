package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// defaultReadHeaderTimeout bounds slow-header (slowloris) clients on every
// listener.
const defaultReadHeaderTimeout = 30 * time.Second

// protocolSetters dispatches configured protocol names onto http.Protocols.
var protocolSetters = map[string]func(*http.Protocols){
	ProtocolH1: func(p *http.Protocols) { p.SetHTTP1(true) },
	ProtocolH2: func(p *http.Protocols) { p.SetHTTP2(true) },
}

// serverProtocols maps a validated listener protocol list onto
// http.Protocols. An empty list enables HTTP/1.1 and HTTP/2.
func serverProtocols(names []string) *http.Protocols {
	p := new(http.Protocols)
	if len(names) == 0 {
		p.SetHTTP1(true)
		p.SetHTTP2(true)
		return p
	}
	for _, n := range names {
		if set, ok := protocolSetters[n]; ok {
			set(p)
		}
	}
	return p
}

// listenerRuntime is one bound listener with its serving http.Server.
type listenerRuntime struct {
	cfg    ListenerConfig
	server *http.Server
	ln     net.Listener
}

// ListenerStatus reports one listener's configuration and bound address.
type ListenerStatus struct {
	ID      string
	Address string
	// BoundAddress is the actual bound address (resolving ":0" ports) when
	// the engine is started, empty otherwise.
	BoundAddress string
	TLS          bool
}

// Start binds every configured listener and begins serving the shared
// handler. Listeners are bound synchronously, so the bound addresses in
// Status are valid as soon as Start returns. TLS is taken from
// Deps.ServerTLS; plain listeners are permitted only when every route is
// public (enforced by New and Reload).
func (e *Engine) Start() error {
	if !e.started.CompareAndSwap(false, true) {
		return ErrEngineStarted
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.state.Load()
	runtimes := make([]*listenerRuntime, 0, len(st.cfg.Listeners))
	for i := range st.cfg.Listeners {
		lc := st.cfg.Listeners[i]
		ln, err := net.Listen("tcp", lc.Address)
		if err != nil {
			closeListeners(runtimes, e.deps.Logger)
			e.started.Store(false)
			return &ListenerError{ID: lc.ID, Err: err}
		}
		srv := &http.Server{
			Handler:           e,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			Protocols:         serverProtocols(lc.Protocols),
			ErrorLog:          slog.NewLogLogger(e.deps.Logger.Handler(), slog.LevelError),
		}
		if e.deps.ServerTLS != nil {
			srv.TLSConfig = e.deps.ServerTLS.Clone()
		}
		runtimes = append(runtimes, &listenerRuntime{cfg: lc, server: srv, ln: ln})
	}
	e.listeners = runtimes
	for _, rt := range runtimes {
		e.wg.Add(1)
		go e.serve(rt)
	}
	return nil
}

func (e *Engine) serve(rt *listenerRuntime) {
	defer e.wg.Done()
	var err error
	if rt.server.TLSConfig != nil {
		err = rt.server.ServeTLS(rt.ln, "", "")
	} else {
		err = rt.server.Serve(rt.ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		e.deps.Logger.Error("proxy: listener terminated", "listener", rt.cfg.ID, "error", err)
	}
}

// Stop gracefully shuts down all listeners, waiting for in-flight requests
// up to the context deadline. It is a no-op when the engine is not started.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started.Load() {
		return nil
	}
	var errs []error
	for _, rt := range e.listeners {
		if err := rt.server.Shutdown(ctx); err != nil {
			errs = append(errs, &ListenerError{ID: rt.cfg.ID, Err: err})
			// Graceful shutdown failed (context expired); force-close the
			// remaining connections so Stop never leaks a running server.
			if cerr := rt.server.Close(); cerr != nil && !errors.Is(cerr, http.ErrServerClosed) {
				errs = append(errs, &ListenerError{ID: rt.cfg.ID, Err: cerr})
			}
		}
	}
	e.wg.Wait()
	e.listeners = nil
	e.started.Store(false)
	return errors.Join(errs...)
}

func closeListeners(runtimes []*listenerRuntime, logger *slog.Logger) {
	for _, rt := range runtimes {
		if err := rt.ln.Close(); err != nil {
			logger.Error("proxy: closing listener", "listener", rt.cfg.ID, "error", err)
		}
	}
}
