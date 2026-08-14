package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cespare/xxhash/v2"
)

// Transport defaults applied when the pool configuration leaves them unset.
const (
	defaultMaxIdleConnsPerHost = 128
	defaultIdleConnTimeout     = 90 * time.Second
	defaultDialTimeout         = 30 * time.Second
	defaultKeepAlive           = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultExpectContinue      = time.Second
)

// backend is one compiled backend endpoint.
type backend struct {
	url    *url.URL
	weight int
}

// compiledPool is an immutable compiled backend pool sharing one long-lived
// pooled transport across all its backends and routes.
type compiledPool struct {
	cfg       BackendPoolConfig
	cfgHash   uint64
	transport *http.Transport
	backends  []*backend
	balancer  Balancer
}

// poolConfigHash returns a deterministic hash of the pool configuration,
// used to decide whether a pool's transport can be carried across a Reload.
func poolConfigHash(pc *BackendPoolConfig) uint64 {
	return xxhash.Sum64String(fmt.Sprintf("%#v", *pc))
}

// compilePools compiles all pools, carrying the *http.Transport (and its
// warm connections) of any pool whose ID and configuration are unchanged
// from prev. It returns the transports of changed or removed pools so the
// caller can CloseIdleConnections them after the state swap.
func compilePools(cfg *Config, deps Deps, prev map[string]*compiledPool) (map[string]*compiledPool, []*http.Transport, error) {
	pools := make(map[string]*compiledPool, len(cfg.Pools))
	for i := range cfg.Pools {
		pc := cfg.Pools[i]
		backends, err := parseBackends(&pc)
		if err != nil {
			return nil, nil, err
		}
		balancer, err := newBalancer(pc.Balancer)
		if err != nil {
			return nil, nil, &ConfigError{Kind: "pool", ID: pc.ID, Err: err}
		}
		hash := poolConfigHash(&pc)
		var transport *http.Transport
		if old, ok := prev[pc.ID]; ok && old.cfgHash == hash {
			transport = old.transport
		} else {
			transport, err = buildTransport(&pc, backends, deps)
			if err != nil {
				return nil, nil, err
			}
		}
		pools[pc.ID] = &compiledPool{
			cfg:       pc,
			cfgHash:   hash,
			transport: transport,
			backends:  backends,
			balancer:  balancer,
		}
	}
	var retired []*http.Transport
	for id, old := range prev {
		if np, ok := pools[id]; !ok || np.transport != old.transport {
			retired = append(retired, old.transport)
		}
	}
	return pools, retired, nil
}

func parseBackends(pc *BackendPoolConfig) ([]*backend, error) {
	backends := make([]*backend, 0, len(pc.Backends))
	for _, bc := range pc.Backends {
		u, err := url.Parse(bc.URL)
		if err != nil || u.Host == "" {
			return nil, &ConfigError{Kind: "pool", ID: pc.ID, Err: ErrInvalidBackendURL}
		}
		backends = append(backends, &backend{url: u, weight: bc.Weight})
	}
	return backends, nil
}

// buildTransport builds the long-lived pooled transport for one pool. When
// the pool declares a TLS trust class, the client TLS configuration is
// resolved through the injected TrustResolver using the first backend's host
// as the representative endpoint.
func buildTransport(pc *BackendPoolConfig, backends []*backend, deps Deps) (*http.Transport, error) {
	maxIdle := pc.MaxIdleConnsPerHost
	if maxIdle <= 0 {
		maxIdle = defaultMaxIdleConnsPerHost
	}
	idleTimeout := pc.IdleConnTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleConnTimeout
	}
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   maxIdle,
		IdleConnTimeout:       idleTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinue,
	}
	if pc.TLS.TrustClass != "" {
		endpoint := backends[0].url.Host
		tlsCfg, err := deps.Trust.ClientTLSConfig(context.Background(), pc.TLS.TrustClass, endpoint)
		if err != nil {
			return nil, &TrustResolveError{PoolID: pc.ID, TrustClass: pc.TLS.TrustClass, Err: err}
		}
		tr.TLSClientConfig = tlsCfg
	}
	return tr, nil
}
