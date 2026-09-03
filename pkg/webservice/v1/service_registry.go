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

package v1

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// ReasonServiceNotConfigured is the stable, machine-readable
// discriminator carried by the `reason` field of every service-registry
// 503 body. It is an alias of the canonical constant in the response
// package, which the per-service handlers in
// pkg/webservice/v1/rest/internal/protorest emit for the same condition
// — one contract, one definition, two producers.
const ReasonServiceNotConfigured = response.ReasonServiceNotConfigured

// ServiceUnavailableResponse is the body written for a request that
// lands on a dark surface. Aliased from the response package so the
// registry stub and the per-service handlers write the identical shape.
type ServiceUnavailableResponse = response.ServiceUnavailableResponse

// ServiceRegistry tracks which REST services were wired into the daemon
// at startup. Each entry records the service's URL prefix and whether
// the daemon-side ServiceProvider was nil when the router built itself.
//
// The original behavior was to log at Debug level and silently skip the
// route registration, which made every "service not configured" surface
// as a generic 404 once the dashboard tried to call it. Operators had
// no way to tell the difference between "the URL is wrong" and "the
// daemon forgot to wire this service" without scrolling through Debug
// logs.
//
// With the registry every absent service:
//   - logs at Warn at startup with the prefix that won't be reachable,
//   - registers a 503 catch-all under that prefix so callers see a
//     structured body — carrying the machine-readable
//     ReasonServiceNotConfigured discriminator and the service name —
//     instead of a bare 404, and
//   - shows up on /api/v1/platform/service-registry so the WebUI's
//     Platform → Services view can render the dark surface.
type ServiceRegistry struct {
	mu      sync.RWMutex
	logger  *logging.Logger
	writer  response.HttpWriter
	entries map[string]*ServiceEntry
}

// ServiceEntry is a single service's wire status.
type ServiceEntry struct {
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	Configured bool   `json:"configured"`
	Reason     string `json:"reason,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

// NewServiceRegistry returns an empty registry.
func NewServiceRegistry(logger *logging.Logger, writer response.HttpWriter) *ServiceRegistry {
	return &ServiceRegistry{
		logger:  logger,
		writer:  writer,
		entries: make(map[string]*ServiceEntry),
	}
}

// markConfigured records that the named service was wired and its routes
// were registered successfully.
func (r *ServiceRegistry) markConfigured(name, prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[name] = &ServiceEntry{
		Name:       name,
		Prefix:     prefix,
		Configured: true,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

// markUnconfigured records that the named service was not wired at
// startup. The reason is a short string the operator will see on the
// /platform/service-registry response and in the 503 body.
func (r *ServiceRegistry) markUnconfigured(name, prefix, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[name] = &ServiceEntry{
		Name:       name,
		Prefix:     prefix,
		Configured: false,
		Reason:     reason,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

// Snapshot returns a deterministic, sorted copy of the registry suitable
// for serialization.
func (r *ServiceRegistry) Snapshot() []*ServiceEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ServiceEntry, 0, len(r.entries))
	for _, e := range r.entries {
		cp := *e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// requireService applies the loud-failure policy for a single REST
// surface. If svc is non-nil, the supplied register callback runs and
// the service is recorded as Configured. If svc is nil, register is
// skipped, the registry records Unconfigured with reason, the router
// installs a 503 catch-all under prefix, and the daemon logs a Warn
// line.
//
// prefix MUST be a leading-slash path relative to the API root (e.g.
// "/vtpm" or "/dns"). The 503 stub catches every method on
// <prefix>/... so the caller sees a ServiceUnavailableResponse
// explaining why the surface is dark.
//
// excludePrefixes carves subtrees out of the stub for surfaces owned
// by a DIFFERENT service under the same path prefix (e.g. the
// registry-backed /compute/images inside a dark /compute). The
// exclusion is method-agnostic on purpose: mux keeps scanning after a
// method mismatch, so without it an unsupported method on the live
// carved-out surface would fall through to this stub and be
// misattributed to the dark service.
func (r *ServiceRegistry) requireService(
	router *mux.Router,
	name, prefix string,
	svc any,
	register func(),
	excludePrefixes ...string,
) {
	if !isNilService(svc) {
		register()
		r.markConfigured(name, prefix)
		return
	}

	reason := name + " service not configured by daemon — REST surface is dark"
	r.markUnconfigured(name, prefix, reason)
	if r.logger != nil {
		r.logger.Warnf("REST service %q is not configured; %s/... requests will return 503", name, prefix)
	}

	handler := r.serviceUnavailableHandler(name, reason)
	// PathPrefix matches the base and every subpath; PathPrefix without a
	// trailing slash would also catch unrelated routes that happen to
	// start with the same letters, so we anchor explicitly.
	route := router.PathPrefix(prefix + "/")
	if len(excludePrefixes) > 0 {
		route = route.MatcherFunc(excludeSubtreeMatcher(prefix, excludePrefixes))
	}
	route.HandlerFunc(handler)
	router.HandleFunc(prefix, handler)
}

// excludeSubtreeMatcher returns a mux matcher that rejects requests
// whose path, relative to the stub's OWN prefix boundary, falls inside
// one of the excluded subtrees. Each exclusion must extend prefix
// (e.g. "/compute/images" under "/compute"); its remainder is matched
// segment-aligned against the path AFTER the boundary, so a later
// occurrence of the exclusion text deeper in the URL (e.g.
// "/compute/vms/compute/images") stays with the stub. The boundary is
// the first occurrence of prefix+"/" in the request path — the mount
// (e.g. "/api/v1") never contains it.
func excludeSubtreeMatcher(prefix string, excludePrefixes []string) mux.MatcherFunc {
	remainders := make([]string, 0, len(excludePrefixes))
	for _, ex := range excludePrefixes {
		if rem := strings.TrimPrefix(ex, prefix); rem != ex && rem != "" {
			remainders = append(remainders, rem)
		}
	}
	return func(req *http.Request, _ *mux.RouteMatch) bool {
		idx := strings.Index(req.URL.Path, prefix+"/")
		if idx < 0 {
			return true
		}
		rest := req.URL.Path[idx+len(prefix):]
		for _, rem := range remainders {
			if rest == rem || strings.HasPrefix(rest, rem+"/") {
				return false
			}
		}
		return true
	}
}

// RegisterStatusEndpoint mounts GET /platform/service-registry on the
// supplied subrouter. The response is a single JSON envelope listing
// every service the daemon knows about and whether its routes were
// wired.
func (r *ServiceRegistry) RegisterStatusEndpoint(router *mux.Router) {
	router.HandleFunc("/platform/service-registry", func(w http.ResponseWriter, req *http.Request) {
		if r.writer == nil {
			http.Error(w, "registry: response writer not configured", http.StatusInternalServerError)
			return
		}
		entries := r.Snapshot()
		configured := 0
		for _, e := range entries {
			if e.Configured {
				configured++
			}
		}
		r.writer.Success200(w, req, map[string]any{
			"services":   entries,
			"total":      len(entries),
			"configured": configured,
			"dark":       len(entries) - configured,
		})
	}).Methods("GET")
}

func (r *ServiceRegistry) serviceUnavailableHandler(name, reason string) http.HandlerFunc {
	body := response.NewServiceUnavailableResponse(name, reason)
	// The body is fixed at registration time, so serialize the
	// nil-writer form once rather than on every request.
	fallback, err := json.Marshal(body)
	if err != nil && r.logger != nil {
		// Unreachable for a struct of strings and ints, but the stub
		// must answer either way, so record it and degrade to prose.
		r.logger.Errorf("REST service %q: marshaling the 503 body failed: %v", name, err)
	}
	return func(w http.ResponseWriter, req *http.Request) {
		if r.writer == nil {
			if fallback == nil {
				http.Error(w, reason, http.StatusServiceUnavailable)
				return
			}
			// Still JSON, still carrying the discriminator — a client
			// must never have to parse prose because the router was
			// built without a response writer.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write(fallback)
			return
		}
		r.writer.Write(w, req, http.StatusServiceUnavailable, body)
	}
}

// isNilService returns true if the supplied service handle is either a
// literal nil interface or a typed-nil interface (a common Go gotcha —
// `var x *VTPMService; svc = x; svc == nil` is FALSE because the
// interface carries a non-nil type). The router's existing nil checks
// catch literal nils only.
func isNilService(svc any) bool {
	if svc == nil {
		return true
	}
	v := reflect.ValueOf(svc)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return v.IsNil()
	}
	return false
}
