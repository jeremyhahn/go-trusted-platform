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
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

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
//     structured "<service> service not configured" body instead of a
//     bare 404, and
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
// <prefix>/... so the caller sees a structured body explaining why the
// surface is dark.
func (r *ServiceRegistry) requireService(
	router *mux.Router,
	name, prefix string,
	svc any,
	register func(),
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
	router.PathPrefix(prefix + "/").HandlerFunc(handler)
	router.HandleFunc(prefix, handler)
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
	body := map[string]any{
		"code":    http.StatusServiceUnavailable,
		"error":   reason,
		"success": false,
		"service": name,
	}
	return func(w http.ResponseWriter, req *http.Request) {
		if r.writer == nil {
			http.Error(w, reason, http.StatusServiceUnavailable)
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
