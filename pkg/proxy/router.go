package proxy

import (
	"net"
	"net/http/httputil"
	"sort"
	"strings"
)

// CompiledRoute is an immutable, compiled route: its configuration (with
// auth defaults merged), its backend pool, its shared reverse proxy, and its
// metrics counters. Instances are shared across requests and never mutated
// after compilation.
type CompiledRoute struct {
	cfg     RouteConfig
	pool    *compiledPool
	rp      *httputil.ReverseProxy
	metrics *routeMetrics
}

// Config returns a copy of the route configuration with auth defaults merged.
func (cr *CompiledRoute) Config() RouteConfig { return cr.cfg }

// hostRoutes holds the routes for one host, sorted by descending path prefix
// length so the longest prefix wins.
type hostRoutes struct {
	routes []*CompiledRoute
}

func (hr *hostRoutes) match(path string) *CompiledRoute {
	for _, cr := range hr.routes {
		if matchPrefix(path, cr.cfg.PathPrefix) {
			return cr
		}
	}
	return nil
}

// routeTable is the immutable compiled routing table. A new table is built on
// every Reload and published through an atomic pointer, so matching is
// lock-free.
type routeTable struct {
	hosts    map[string]*hostRoutes
	wildcard *hostRoutes
}

// match resolves the route for a request host and path. The host may carry a
// port, which is stripped, and matching is case-insensitive. Exact-host
// routes are consulted before wildcard routes. It returns nil when no route
// matches.
func (t *routeTable) match(host, path string) *CompiledRoute {
	h := normalizeHost(host)
	if hr, ok := t.hosts[h]; ok {
		if cr := hr.match(path); cr != nil {
			return cr
		}
	}
	if t.wildcard != nil {
		return t.wildcard.match(path)
	}
	return nil
}

// buildRouteTable groups compiled routes by host and sorts each host's routes
// by descending path prefix length. Routes with no Hosts entries are treated
// as wildcard routes.
func buildRouteTable(routes []*CompiledRoute) *routeTable {
	t := &routeTable{hosts: make(map[string]*hostRoutes)}
	for _, cr := range routes {
		hosts := cr.cfg.Hosts
		if len(hosts) == 0 {
			hosts = []string{WildcardHost}
		}
		for _, h := range hosts {
			h = strings.ToLower(h)
			if h == WildcardHost {
				if t.wildcard == nil {
					t.wildcard = &hostRoutes{}
				}
				t.wildcard.routes = append(t.wildcard.routes, cr)
				continue
			}
			hr := t.hosts[h]
			if hr == nil {
				hr = &hostRoutes{}
				t.hosts[h] = hr
			}
			hr.routes = append(hr.routes, cr)
		}
	}
	for _, hr := range t.hosts {
		sortByPrefixLen(hr.routes)
	}
	if t.wildcard != nil {
		sortByPrefixLen(t.wildcard.routes)
	}
	return t
}

func sortByPrefixLen(routes []*CompiledRoute) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].cfg.PathPrefix) > len(routes[j].cfg.PathPrefix)
	})
}

// normalizeHost strips an optional port and lowercases the host. Already
// lowercase hosts without a port incur no allocation.
func normalizeHost(host string) string {
	if strings.IndexByte(host, ':') >= 0 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return strings.ToLower(host)
}

// matchPrefix reports whether path falls under prefix on a path-segment
// boundary: "/api" matches "/api" and "/api/v1" but not "/apiary".
func matchPrefix(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}
