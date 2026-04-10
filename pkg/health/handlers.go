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

package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// HealthResponse is the JSON response structure for health endpoints.
type HealthResponse struct {
	Status     string                 `json:"status"`
	Healthy    bool                   `json:"healthy"`
	Timestamp  time.Time              `json:"timestamp"`
	Duration   string                 `json:"duration,omitempty"`
	Components []ComponentResponse    `json:"components,omitempty"`
	Counts     *HealthCounts          `json:"counts,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// ComponentResponse is the JSON response structure for a single component.
type ComponentResponse struct {
	Name        string                 `json:"name"`
	Status      string                 `json:"status"`
	Healthy     bool                   `json:"healthy"`
	Message     string                 `json:"message,omitempty"`
	Duration    string                 `json:"duration,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// HealthCounts contains counts of components by status.
type HealthCounts struct {
	Total     int `json:"total"`
	Healthy   int `json:"healthy"`
	Degraded  int `json:"degraded"`
	Unhealthy int `json:"unhealthy"`
	Unknown   int `json:"unknown"`
}

// ProbeResponse is the JSON response structure for probe endpoints.
type ProbeResponse struct {
	Status    string    `json:"status"`
	OK        bool      `json:"ok"`
	Timestamp time.Time `json:"timestamp"`
}

// HandlerOption is a functional option for configuring handlers.
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	timeout        time.Duration
	includeDetails bool
	verbose        bool
}

// WithHandlerTimeout sets the timeout for health checks in handlers.
func WithHandlerTimeout(timeout time.Duration) HandlerOption {
	return func(c *handlerConfig) {
		c.timeout = timeout
	}
}

// WithIncludeDetails enables or disables detailed component information.
func WithIncludeDetails(include bool) HandlerOption {
	return func(c *handlerConfig) {
		c.includeDetails = include
	}
}

// WithVerbose enables verbose output in responses.
func WithVerbose(verbose bool) HandlerOption {
	return func(c *handlerConfig) {
		c.verbose = verbose
	}
}

func defaultHandlerConfig() *handlerConfig {
	return &handlerConfig{
		timeout:        30 * time.Second,
		includeDetails: true,
		verbose:        false,
	}
}

// NewHealthHandler creates an HTTP handler for the /health endpoint.
// It returns detailed health information for all registered components.
func NewHealthHandler(registry Registry, opts ...HandlerOption) http.Handler {
	config := defaultHandlerConfig()
	for _, opt := range opts {
		opt(config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.timeout)
		defer cancel()

		health := registry.Check(ctx)

		response := HealthResponse{
			Status:    health.Status.String(),
			Healthy:   health.Status.IsHealthy(),
			Timestamp: health.Timestamp,
			Duration:  health.TotalDurationString(),
		}

		if config.includeDetails {
			response.Components = make([]ComponentResponse, len(health.Components))
			for i, comp := range health.Components {
				response.Components[i] = ComponentResponse{
					Name:        comp.Name,
					Status:      comp.Status.String(),
					Healthy:     comp.Status.IsHealthy(),
					Message:     comp.Message,
					Duration:    comp.DurationString(),
					LastChecked: comp.LastChecked,
					Details:     comp.Details,
				}
			}

			response.Counts = &HealthCounts{
				Total:     health.ComponentCount(),
				Healthy:   health.HealthyCount,
				Degraded:  health.DegradedCount,
				Unhealthy: health.UnhealthyCount,
				Unknown:   health.UnknownCount,
			}
		}

		statusCode := http.StatusOK
		switch health.Status {
		case StatusUnhealthy:
			statusCode = http.StatusServiceUnavailable
		case StatusDegraded:
			statusCode = http.StatusOK // Degraded is still serving
		}

		writeJSONResponse(w, statusCode, response)
	})
}

// NewLivenessHandler creates an HTTP handler for the /healthz or /livez endpoint.
// It returns a simple response indicating if the application is alive.
func NewLivenessHandler(probe Probe, opts ...HandlerOption) http.Handler {
	config := defaultHandlerConfig()
	for _, opt := range opts {
		opt(config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.timeout)
		defer cancel()

		ok := probe.Check(ctx)

		response := ProbeResponse{
			Status:    "ok",
			OK:        ok,
			Timestamp: time.Now(),
		}

		statusCode := http.StatusOK
		if !ok {
			response.Status = "fail"
			statusCode = http.StatusServiceUnavailable
		}

		writeJSONResponse(w, statusCode, response)
	})
}

// NewReadinessHandler creates an HTTP handler for the /ready or /readyz endpoint.
// It returns a simple response indicating if the application is ready to serve traffic.
func NewReadinessHandler(probe Probe, opts ...HandlerOption) http.Handler {
	config := defaultHandlerConfig()
	for _, opt := range opts {
		opt(config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.timeout)
		defer cancel()

		ok := probe.Check(ctx)

		response := ProbeResponse{
			Status:    "ready",
			OK:        ok,
			Timestamp: time.Now(),
		}

		statusCode := http.StatusOK
		if !ok {
			response.Status = "not_ready"
			statusCode = http.StatusServiceUnavailable
		}

		writeJSONResponse(w, statusCode, response)
	})
}

// NewStartupHandler creates an HTTP handler for the /startup endpoint.
// It returns a simple response indicating if the application has started.
func NewStartupHandler(probe Probe, opts ...HandlerOption) http.Handler {
	config := defaultHandlerConfig()
	for _, opt := range opts {
		opt(config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.timeout)
		defer cancel()

		ok := probe.Check(ctx)

		response := ProbeResponse{
			Status:    "started",
			OK:        ok,
			Timestamp: time.Now(),
		}

		statusCode := http.StatusOK
		if !ok {
			response.Status = "starting"
			statusCode = http.StatusServiceUnavailable
		}

		writeJSONResponse(w, statusCode, response)
	})
}

// NewComponentHealthHandler creates an HTTP handler for checking a specific component.
// The component name is extracted from the URL path parameter.
func NewComponentHealthHandler(registry Registry, componentName string, opts ...HandlerOption) http.Handler {
	config := defaultHandlerConfig()
	for _, opt := range opts {
		opt(config)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.timeout)
		defer cancel()

		comp, err := registry.CheckComponent(ctx, componentName)
		if err != nil {
			writeJSONResponse(w, http.StatusNotFound, map[string]string{
				"error":     "component not found",
				"component": componentName,
			})
			return
		}

		response := ComponentResponse{
			Name:        comp.Name,
			Status:      comp.Status.String(),
			Healthy:     comp.Status.IsHealthy(),
			Message:     comp.Message,
			Duration:    comp.DurationString(),
			LastChecked: comp.LastChecked,
		}

		if config.includeDetails {
			response.Details = comp.Details
		}

		statusCode := http.StatusOK
		if comp.Status == StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		}

		writeJSONResponse(w, statusCode, response)
	})
}

// HealthMux creates a new http.ServeMux with standard health endpoints configured.
func HealthMux(registry Registry, livenessProbe Probe, readinessProbe Probe, opts ...HandlerOption) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("/health", NewHealthHandler(registry, opts...))
	mux.Handle("/healthz", NewLivenessHandler(livenessProbe, opts...))
	mux.Handle("/livez", NewLivenessHandler(livenessProbe, opts...))
	mux.Handle("/ready", NewReadinessHandler(readinessProbe, opts...))
	mux.Handle("/readyz", NewReadinessHandler(readinessProbe, opts...))

	return mux
}

// HealthMuxWithStartup creates a new http.ServeMux with standard health endpoints including startup probe.
func HealthMuxWithStartup(registry Registry, livenessProbe, readinessProbe, startupProbe Probe, opts ...HandlerOption) *http.ServeMux {
	mux := HealthMux(registry, livenessProbe, readinessProbe, opts...)
	mux.Handle("/startup", NewStartupHandler(startupProbe, opts...))
	return mux
}

func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
