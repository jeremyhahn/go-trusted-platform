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

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// HealthCheckable is an optional interface that services can implement
// to provide custom health check logic. If not implemented, the health
// checker falls back to checking IsRunning().
type HealthCheckable interface {
	// HealthCheck performs a health check and returns nil if healthy,
	// or an error describing the unhealthy condition.
	HealthCheck(ctx context.Context) error
}

// ServiceHealthChecker wraps a ManagedService to implement the health.HealthChecker
// interface. It provides health status based on the service's running state and
// optionally calls the service's HealthCheck method if implemented.
type ServiceHealthChecker struct {
	service ManagedService
}

// NewServiceHealthChecker creates a new health checker for a managed service.
func NewServiceHealthChecker(service ManagedService) *ServiceHealthChecker {
	if service == nil {
		return nil
	}
	return &ServiceHealthChecker{
		service: service,
	}
}

// Name returns the name of the service being checked.
func (c *ServiceHealthChecker) Name() string {
	if c.service == nil {
		return "unknown"
	}
	return c.service.Name()
}

// Check performs a health check on the wrapped service.
// If the service implements HealthCheckable, it calls the HealthCheck method.
// Otherwise, it checks the IsRunning state.
func (c *ServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.service == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "service reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["service_name"] = c.service.Name()

	// Check if service is running
	if !c.service.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "service is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true

	// If service implements HealthCheckable, use its custom health check
	if healthCheckable, ok := c.service.(HealthCheckable); ok {
		if err := healthCheckable.HealthCheck(ctx); err != nil {
			componentHealth.Status = health.StatusDegraded
			componentHealth.Message = err.Error()
			componentHealth.Details["health_check_error"] = err.Error()
			componentHealth.Duration = time.Since(start)
			return componentHealth
		}
		componentHealth.Details["custom_health_check"] = "passed"
	}

	// Service is running and passed health checks
	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "service is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// CAServiceHealthChecker wraps the CAGRPCService for health checking.
// It checks CA initialization status and certificate validity.
type CAServiceHealthChecker struct {
	service *CAGRPCService
}

// NewCAServiceHealthChecker creates a new health checker for the CA service.
func NewCAServiceHealthChecker(service *CAGRPCService) *CAServiceHealthChecker {
	if service == nil {
		return nil
	}
	return &CAServiceHealthChecker{
		service: service,
	}
}

// Name returns the name of the CA service.
func (c *CAServiceHealthChecker) Name() string {
	return "ca"
}

// Check performs a health check on the CA service.
func (c *CAServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.service == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "CA service reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	// Check if CA is configured
	if c.service.ca == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "Certificate Authority not initialized"
		componentHealth.Details["ca_initialized"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["ca_initialized"] = true

	// Check if CA is initialized (has root cert, etc.)
	isInitialized := c.service.ca.IsInitialized()
	componentHealth.Details["is_initialized"] = isInitialized

	if !isInitialized {
		componentHealth.Status = health.StatusDegraded
		componentHealth.Message = "CA configured but not fully initialized"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	// Get CA identity
	componentHealth.Details["identity"] = c.service.ca.Identity()

	// Check root certificate validity
	rootCert, err := c.service.ca.TrustedRoot()
	if err != nil {
		componentHealth.Status = health.StatusDegraded
		componentHealth.Message = "Failed to get trusted root certificate"
		componentHealth.Details["root_cert_error"] = err.Error()
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if rootCert != nil {
		now := time.Now()
		componentHealth.Details["root_cn"] = rootCert.Subject.CommonName
		componentHealth.Details["root_not_before"] = rootCert.NotBefore.Format(time.RFC3339)
		componentHealth.Details["root_not_after"] = rootCert.NotAfter.Format(time.RFC3339)

		// Check if root certificate is expired or not yet valid
		if now.Before(rootCert.NotBefore) {
			componentHealth.Status = health.StatusDegraded
			componentHealth.Message = "Root certificate not yet valid"
			componentHealth.Duration = time.Since(start)
			return componentHealth
		}
		if now.After(rootCert.NotAfter) {
			componentHealth.Status = health.StatusUnhealthy
			componentHealth.Message = "Root certificate has expired"
			componentHealth.Duration = time.Since(start)
			return componentHealth
		}

		// Warn if certificate expires within 30 days
		expiresIn := rootCert.NotAfter.Sub(now)
		if expiresIn < 30*24*time.Hour {
			componentHealth.Status = health.StatusDegraded
			componentHealth.Message = "Root certificate expires soon"
			componentHealth.Details["expires_in_days"] = int(expiresIn.Hours() / 24)
			componentHealth.Duration = time.Since(start)
			return componentHealth
		}
	}

	// Check intermediate certificate if available
	intermediateCert, err := c.service.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		now := time.Now()
		componentHealth.Details["intermediate_cn"] = intermediateCert.Subject.CommonName
		componentHealth.Details["intermediate_not_after"] = intermediateCert.NotAfter.Format(time.RFC3339)

		if now.After(intermediateCert.NotAfter) {
			componentHealth.Status = health.StatusUnhealthy
			componentHealth.Message = "Intermediate certificate has expired"
			componentHealth.Duration = time.Since(start)
			return componentHealth
		}
	}

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "CA service is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// SDNServiceHealthChecker wraps the SDNService for health checking.
// It checks OVS connectivity in addition to the running state.
type SDNServiceHealthChecker struct {
	service *SDNService
}

// NewSDNServiceHealthChecker creates a new health checker for the SDN service.
func NewSDNServiceHealthChecker(service *SDNService) *SDNServiceHealthChecker {
	if service == nil {
		return nil
	}
	return &SDNServiceHealthChecker{
		service: service,
	}
}

// Name returns the name of the SDN service.
func (c *SDNServiceHealthChecker) Name() string {
	return "sdn"
}

// Check performs a health check on the SDN service.
func (c *SDNServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.service == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "SDN service reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	// SDN service doesn't have IsRunning, check if OVS client is connected
	if c.service.ovsClient == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "OVS client not initialized"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	// Try to list bridges as a connectivity check
	c.service.mu.RLock()
	bridgeCount := len(c.service.bridges)
	portCount := len(c.service.ports)
	c.service.mu.RUnlock()

	componentHealth.Details["bridge_count"] = bridgeCount
	componentHealth.Details["port_count"] = portCount
	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "SDN service is operational"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// KMSServiceHealthChecker wraps the KMSService for health checking.
type KMSServiceHealthChecker struct {
	service *KMSService
}

// NewKMSServiceHealthChecker creates a new health checker for the KMS service.
func NewKMSServiceHealthChecker(service *KMSService) *KMSServiceHealthChecker {
	if service == nil {
		return nil
	}
	return &KMSServiceHealthChecker{
		service: service,
	}
}

// Name returns the name of the KMS service.
func (c *KMSServiceHealthChecker) Name() string {
	return "kms"
}

// Check performs a health check on the KMS service.
func (c *KMSServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.service == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "KMS service reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if !c.service.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "KMS service is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true
	componentHealth.Details["kms_server_ready"] = c.service.KMSServer() != nil

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "KMS service is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// TenantServiceHealthChecker wraps the TenantService for health checking.
type TenantServiceHealthChecker struct {
	service *TenantService
}

// NewTenantServiceHealthChecker creates a new health checker for the tenant service.
func NewTenantServiceHealthChecker(service *TenantService) *TenantServiceHealthChecker {
	if service == nil {
		return nil
	}
	return &TenantServiceHealthChecker{
		service: service,
	}
}

// Name returns the name of the tenant service.
func (c *TenantServiceHealthChecker) Name() string {
	return "tenant"
}

// Check performs a health check on the tenant service.
func (c *TenantServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.service == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "tenant service reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if !c.service.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "tenant service is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "tenant service is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// QUICServerHealthChecker wraps the QUIC Server for health checking.
type QUICServerHealthChecker struct {
	server *quic.Server
}

// NewQUICServerHealthChecker creates a new health checker for the QUIC server.
func NewQUICServerHealthChecker(server *quic.Server) *QUICServerHealthChecker {
	if server == nil {
		return nil
	}
	return &QUICServerHealthChecker{
		server: server,
	}
}

// Name returns the name of the QUIC service.
func (c *QUICServerHealthChecker) Name() string {
	return "quic"
}

// Check performs a health check on the QUIC server.
func (c *QUICServerHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.server == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "QUIC server reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if !c.server.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "QUIC server is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true
	componentHealth.Details["listen_addr"] = c.server.ListenAddr()

	// Get server stats if available
	stats := c.server.Stats()
	if stats != nil {
		componentHealth.Details["active_connections"] = stats.ActiveConnections
		componentHealth.Details["total_connections"] = stats.TotalConnections
		componentHealth.Details["requests_handled"] = stats.RequestsHandled
		componentHealth.Details["errors"] = stats.Errors
	}

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "QUIC server is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// RESTServiceHealthChecker wraps the RESTServer for health checking.
type RESTServiceHealthChecker struct {
	server *RESTServer
}

// NewRESTServiceHealthChecker creates a new health checker for the REST server.
func NewRESTServiceHealthChecker(server *RESTServer) *RESTServiceHealthChecker {
	if server == nil {
		return nil
	}
	return &RESTServiceHealthChecker{
		server: server,
	}
}

// Name returns the name of the REST service.
func (c *RESTServiceHealthChecker) Name() string {
	return "rest"
}

// Check performs a health check on the REST server.
func (c *RESTServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.server == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "REST server reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if !c.server.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "REST server is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true
	componentHealth.Details["listen_addr"] = c.server.config.RESTListenAddr
	componentHealth.Details["tls_enabled"] = c.server.config.RESTTLSCertFile != ""
	componentHealth.Details["cors_enabled"] = c.server.config.RESTConfig.EnableCORS
	componentHealth.Details["compression_enabled"] = c.server.config.RESTConfig.EnableCompression

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "REST server is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}

// MCPServiceHealthChecker wraps the MCP Server for health checking.
type MCPServiceHealthChecker struct {
	server *mcp.Server
}

// NewMCPServiceHealthChecker creates a new health checker for the MCP server.
func NewMCPServiceHealthChecker(server *mcp.Server) *MCPServiceHealthChecker {
	if server == nil {
		return nil
	}
	return &MCPServiceHealthChecker{
		server: server,
	}
}

// Name returns the name of the MCP service.
func (c *MCPServiceHealthChecker) Name() string {
	return "mcp"
}

// Check performs a health check on the MCP server.
func (c *MCPServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.server == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "MCP server reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if !c.server.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "MCP server is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "MCP server is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}
