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
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ListServices handles GET /api/v1/platform/services
func (h *PlatformHandlers) ListServices(w http.ResponseWriter, r *http.Request) {
	if h.servicesManager == nil {
		h.respWriter.Error500(w, r, ErrServiceRegistryNotConfigured{})
		return
	}

	ctx := r.Context()
	resp, err := h.servicesManager.ListServices(ctx, &platformv1.ListServicesRequest{})
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}

	services := make([]ServiceInfoResponse, 0, len(resp.Services))
	for _, svc := range resp.Services {
		var startedAt time.Time
		var uptime string
		if svc.StartedAt != nil {
			startedAt = svc.StartedAt.AsTime()
			uptime = time.Since(startedAt).String()
		}

		svcInfo := ServiceInfoResponse{
			Name:       svc.Name,
			Status:     serviceStatusToString(svc.Status),
			StartedAt:  startedAt,
			Uptime:     uptime,
			StartCount: parseUint64FromMetadata(svc.Metadata, "start_count"),
			StopCount:  parseUint64FromMetadata(svc.Metadata, "stop_count"),
			LastError:  svc.Metadata["last_error"],
		}
		services = append(services, svcInfo)
	}

	h.respWriter.Success200(w, r, ServicesListResponse{
		Services:  services,
		Count:     len(services),
		Timestamp: time.Now().Unix(),
	})
}

// GetService handles GET /api/v1/platform/services/{service}
func (h *PlatformHandlers) GetService(w http.ResponseWriter, r *http.Request) {
	if h.servicesManager == nil {
		h.respWriter.Error500(w, r, ErrServiceRegistryNotConfigured{})
		return
	}

	vars := mux.Vars(r)
	serviceName := vars["service"]

	ctx := r.Context()
	svcType := serviceTypeFromName(serviceName)
	resp, err := h.servicesManager.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{
		Service: svcType,
	})
	if err != nil {
		h.respWriter.Error404(w, r, ErrServiceNotFound{ServiceName: serviceName})
		return
	}

	svc := resp.Service
	var startedAt time.Time
	var uptime string
	if svc.StartedAt != nil {
		startedAt = svc.StartedAt.AsTime()
		uptime = time.Since(startedAt).String()
	}

	svcInfo := ServiceInfoResponse{
		Name:       svc.Name,
		Status:     serviceStatusToString(svc.Status),
		StartedAt:  startedAt,
		Uptime:     uptime,
		StartCount: parseUint64FromMetadata(svc.Metadata, "start_count"),
		StopCount:  parseUint64FromMetadata(svc.Metadata, "stop_count"),
		LastError:  svc.Metadata["last_error"],
	}

	h.respWriter.Success200(w, r, svcInfo)
}

// StartService handles POST /api/v1/platform/services/{service}/start
func (h *PlatformHandlers) StartService(w http.ResponseWriter, r *http.Request) {
	if h.servicesManager == nil {
		h.respWriter.Error500(w, r, ErrServiceRegistryNotConfigured{})
		return
	}

	vars := mux.Vars(r)
	serviceName := vars["service"]

	ctx := r.Context()
	svcType := serviceTypeFromName(serviceName)

	_, err := h.servicesManager.StartService(ctx, &platformv1.StartServiceRequest{
		Service: svcType,
	})
	if err != nil {
		// Check for specific error types
		h.writeServiceError(w, r, err, ErrServiceStartFailed{ServiceName: serviceName, Reason: err.Error()})
		return
	}

	h.respWriter.Success200(w, r, ServiceActionResponse{
		Service: serviceName,
		Action:  "start",
		Success: true,
		Message: "service started successfully",
	})
}

// StopService handles POST /api/v1/platform/services/{service}/stop
func (h *PlatformHandlers) StopService(w http.ResponseWriter, r *http.Request) {
	if h.servicesManager == nil {
		h.respWriter.Error500(w, r, ErrServiceRegistryNotConfigured{})
		return
	}

	vars := mux.Vars(r)
	serviceName := vars["service"]

	ctx := r.Context()
	svcType := serviceTypeFromName(serviceName)

	_, err := h.servicesManager.StopService(ctx, &platformv1.StopServiceRequest{
		Service: svcType,
	})
	if err != nil {
		h.writeServiceError(w, r, err, ErrServiceStopFailed{ServiceName: serviceName, Reason: err.Error()})
		return
	}

	h.respWriter.Success200(w, r, ServiceActionResponse{
		Service: serviceName,
		Action:  "stop",
		Success: true,
		Message: "service stopped successfully",
	})
}

// RestartService handles POST /api/v1/platform/services/{service}/restart
func (h *PlatformHandlers) RestartService(w http.ResponseWriter, r *http.Request) {
	if h.servicesManager == nil {
		h.respWriter.Error500(w, r, ErrServiceRegistryNotConfigured{})
		return
	}

	vars := mux.Vars(r)
	serviceName := vars["service"]

	ctx := r.Context()
	svcType := serviceTypeFromName(serviceName)

	// Use a reasonable timeout for restart operations
	restartCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := h.servicesManager.RestartService(restartCtx, &platformv1.RestartServiceRequest{
		Service:        svcType,
		TimeoutSeconds: 30,
	})
	if err != nil {
		h.writeServiceError(w, r, err, ErrServiceStartFailed{ServiceName: serviceName, Reason: err.Error()})
		return
	}

	h.respWriter.Success200(w, r, ServiceActionResponse{
		Service: serviceName,
		Action:  "restart",
		Success: true,
		Message: "service restarted successfully",
	})
}

// writeServiceError answers a failed start, stop or restart. A classified
// gRPC status (a refused process-owned service, an unknown service, one
// already running or not running) goes through the shared protorest mapper,
// so REST answers it with the same class as every other transport. Anything
// unclassified is a failure of the verb itself and stays a 500.
func (h *PlatformHandlers) writeServiceError(w http.ResponseWriter, r *http.Request, err error, failure error) {
	switch status.Code(err) {
	case codes.Unknown, codes.Internal:
		h.respWriter.Error500(w, r, failure)
	default:
		protorest.WriteError(w, r, h.respWriter, err)
	}
}

// serviceStatusToString converts a protobuf ServiceStatus to string
func serviceStatusToString(status platformv1.ServiceStatus) string {
	switch status {
	case platformv1.ServiceStatus_SERVICE_STATUS_STOPPED:
		return "stopped"
	case platformv1.ServiceStatus_SERVICE_STATUS_STARTING:
		return "starting"
	case platformv1.ServiceStatus_SERVICE_STATUS_RUNNING:
		return "running"
	case platformv1.ServiceStatus_SERVICE_STATUS_STOPPING:
		return "stopping"
	case platformv1.ServiceStatus_SERVICE_STATUS_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

// serviceTypeFromName converts a service name to protobuf ServiceType
func serviceTypeFromName(name string) platformv1.ServiceType {
	switch name {
	case "tpm":
		return platformv1.ServiceType_SERVICE_TYPE_TPM
	case "sdn":
		return platformv1.ServiceType_SERVICE_TYPE_SDN
	case "compute":
		return platformv1.ServiceType_SERVICE_TYPE_COMPUTE
	case "dns":
		return platformv1.ServiceType_SERVICE_TYPE_DNS
	case "acme":
		return platformv1.ServiceType_SERVICE_TYPE_ACME
	case "webservice":
		return platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE
	case "attestation":
		return platformv1.ServiceType_SERVICE_TYPE_ATTESTATION
	default:
		return platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED
	}
}

// parseUint64FromMetadata parses a uint64 from service metadata
func parseUint64FromMetadata(metadata map[string]string, key string) uint64 {
	if metadata == nil {
		return 0
	}
	val, ok := metadata[key]
	if !ok {
		return 0
	}
	var result uint64
	for _, c := range val {
		if c >= '0' && c <= '9' {
			result = result*10 + uint64(c-'0')
		} else {
			return 0
		}
	}
	return result
}
