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

package platform

import (
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// ProbeResponse is the /api/v1/platform/liveness and /readiness payload. The verdict
// rides in the body with HTTP 200, unlike the root /health/live and /health/ready
// probes, which answer 503 for orchestrators. It names no component.
type ProbeResponse struct {
	Alive     *bool  `json:"alive,omitempty"`
	Ready     *bool  `json:"ready,omitempty"`
	Status    string `json:"status"`    // health.HealthStatus: healthy, degraded, unhealthy
	Timestamp string `json:"timestamp"` // RFC3339Nano UTC
}

// newProbeResponse copies the status and timestamp of a probe verdict.
func newProbeResponse(probe health.Probe) ProbeResponse {
	return ProbeResponse{
		Status:    string(probe.Status),
		Timestamp: probe.Timestamp.UTC().Format(time.RFC3339Nano),
	}
}

// Liveness handles GET /api/v1/platform/liveness: health.Liveness(), alive set.
func (h *PlatformHandlers) Liveness(w http.ResponseWriter, r *http.Request) {
	probe := health.Liveness()
	resp := newProbeResponse(probe)
	alive := probe.OK
	resp.Alive = &alive
	h.respWriter.Success200(w, r, resp)
}

// Readiness handles GET /api/v1/platform/readiness: health.Readiness(r.Context(), h.healthRegistry), ready set.
func (h *PlatformHandlers) Readiness(w http.ResponseWriter, r *http.Request) {
	probe := health.Readiness(r.Context(), h.healthRegistry)
	resp := newProbeResponse(probe)
	ready := probe.OK
	resp.Ready = &ready
	h.respWriter.Success200(w, r, resp)
}
