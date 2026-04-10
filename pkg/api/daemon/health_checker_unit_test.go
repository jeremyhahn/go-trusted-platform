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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// healthCheckerContextKey is a custom type for context keys in health checker tests.
type healthCheckerContextKey string

// healthCheckerMockManagedService is a test mock that implements ManagedService
// with configurable behavior for all health check tests.
type healthCheckerMockManagedService struct {
	name       string
	running    bool
	startErr   error
	stopErr    error
	healthErr  error
	healthFunc func(ctx context.Context) error
}

func (m *healthCheckerMockManagedService) Name() string {
	return m.name
}

func (m *healthCheckerMockManagedService) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.running = true
	return nil
}

func (m *healthCheckerMockManagedService) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running = false
	return nil
}

func (m *healthCheckerMockManagedService) IsRunning() bool {
	return m.running
}

// healthCheckerMockHealthCheckableService implements both ManagedService and HealthCheckable
type healthCheckerMockHealthCheckableService struct {
	healthCheckerMockManagedService
}

func (m *healthCheckerMockHealthCheckableService) HealthCheck(ctx context.Context) error {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return m.healthErr
}

// TestServiceHealthChecker_CheckAllPaths tests all code paths in ServiceHealthChecker.Check
func TestServiceHealthChecker_CheckAllPaths(t *testing.T) {
	t.Run("nil service returns unhealthy", func(t *testing.T) {
		checker := &ServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "service reference is nil" {
			t.Errorf("Message = %v, want 'service reference is nil'", result.Message)
		}
		if result.Name != "unknown" {
			t.Errorf("Name = %v, want 'unknown'", result.Name)
		}
	})

	t.Run("service not running returns unhealthy", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "test-svc", running: false}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "service is not running" {
			t.Errorf("Message = %v, want 'service is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("service running returns healthy", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "healthy-svc", running: true}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "service is healthy" {
			t.Errorf("Message = %v, want 'service is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if result.Details["service_name"] != "healthy-svc" {
			t.Errorf("Details[service_name] = %v, want 'healthy-svc'", result.Details["service_name"])
		}
	})

	t.Run("HealthCheckable service with failed health check returns degraded", func(t *testing.T) {
		svc := &healthCheckerMockHealthCheckableService{
			healthCheckerMockManagedService: healthCheckerMockManagedService{
				name:      "degraded-svc",
				running:   true,
				healthErr: errors.New("database connection pool exhausted"),
			},
		}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "database connection pool exhausted" {
			t.Errorf("Message = %v, want 'database connection pool exhausted'", result.Message)
		}
		if result.Details["health_check_error"] != "database connection pool exhausted" {
			t.Errorf("Details[health_check_error] = %v, want 'database connection pool exhausted'", result.Details["health_check_error"])
		}
	})

	t.Run("HealthCheckable service with passing health check returns healthy", func(t *testing.T) {
		svc := &healthCheckerMockHealthCheckableService{
			healthCheckerMockManagedService: healthCheckerMockManagedService{
				name:    "fully-healthy-svc",
				running: true,
			},
		}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Details["custom_health_check"] != "passed" {
			t.Errorf("Details[custom_health_check] = %v, want 'passed'", result.Details["custom_health_check"])
		}
	})

	t.Run("response_time_ms is set for healthy service", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "timed-svc", running: true}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set")
		}
	})

	t.Run("duration is positive", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "duration-svc", running: true}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
	})

	t.Run("LastChecked is set", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "time-svc", running: true}
		checker := NewServiceHealthChecker(svc)

		before := time.Now()
		result := checker.Check(context.Background())
		after := time.Now()

		if result.LastChecked.Before(before) || result.LastChecked.After(after) {
			t.Errorf("LastChecked = %v, should be between %v and %v", result.LastChecked, before, after)
		}
	})
}

// TestKMSServiceHealthChecker_CheckAllPaths tests all code paths in KMSServiceHealthChecker.Check
func TestKMSServiceHealthChecker_CheckAllPaths(t *testing.T) {
	t.Run("nil service returns unhealthy", func(t *testing.T) {
		checker := &KMSServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "KMS service reference is nil" {
			t.Errorf("Message = %v, want 'KMS service reference is nil'", result.Message)
		}
	})

	t.Run("service not running returns unhealthy", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(false)
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "KMS service is not running" {
			t.Errorf("Message = %v, want 'KMS service is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("service running returns healthy", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "KMS service is healthy" {
			t.Errorf("Message = %v, want 'KMS service is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if result.Details["kms_server_ready"] != false {
			t.Errorf("Details[kms_server_ready] = %v, want false (nil kmsServer)", result.Details["kms_server_ready"])
		}
	})

	t.Run("response_time_ms is set for healthy service", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}

// TestSDNServiceHealthChecker_CheckAllPaths tests all code paths in SDNServiceHealthChecker.Check
func TestSDNServiceHealthChecker_CheckAllPaths(t *testing.T) {
	t.Run("nil service returns unhealthy", func(t *testing.T) {
		checker := &SDNServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "SDN service reference is nil" {
			t.Errorf("Message = %v, want 'SDN service reference is nil'", result.Message)
		}
	})

	t.Run("OVS client nil returns unhealthy", func(t *testing.T) {
		service := &SDNService{ovsClient: nil}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "OVS client not initialized" {
			t.Errorf("Message = %v, want 'OVS client not initialized'", result.Message)
		}
	})

	t.Run("OVS client initialized returns healthy", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "SDN service is operational" {
			t.Errorf("Message = %v, want 'SDN service is operational'", result.Message)
		}
		if result.Details["bridge_count"] != 0 {
			t.Errorf("Details[bridge_count] = %v, want 0", result.Details["bridge_count"])
		}
		if result.Details["port_count"] != 0 {
			t.Errorf("Details[port_count] = %v, want 0", result.Details["port_count"])
		}
	})

	t.Run("reports accurate bridge and port counts", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges: map[string]*bridgeResource{
				"br-int": {id: "br-int", name: "br-int"},
				"br-ex":  {id: "br-ex", name: "br-ex"},
				"br-tun": {id: "br-tun", name: "br-tun"},
			},
			ports: map[string]*portResource{
				"p1": {id: "p1", name: "p1"},
				"p2": {id: "p2", name: "p2"},
			},
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Details["bridge_count"] != 3 {
			t.Errorf("Details[bridge_count] = %v, want 3", result.Details["bridge_count"])
		}
		if result.Details["port_count"] != 2 {
			t.Errorf("Details[port_count] = %v, want 2", result.Details["port_count"])
		}
	})

	t.Run("response_time_ms is set for healthy service", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}

// TestCAServiceHealthChecker_CheckAllPaths tests all code paths in CAServiceHealthChecker.Check
func TestCAServiceHealthChecker_CheckAllPaths(t *testing.T) {
	t.Run("nil service returns unhealthy", func(t *testing.T) {
		checker := &CAServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "CA service reference is nil" {
			t.Errorf("Message = %v, want 'CA service reference is nil'", result.Message)
		}
	})

	t.Run("CA nil returns unhealthy", func(t *testing.T) {
		service := &CAGRPCService{ca: nil}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "Certificate Authority not initialized" {
			t.Errorf("Message = %v, want 'Certificate Authority not initialized'", result.Message)
		}
		if result.Details["ca_initialized"] != false {
			t.Errorf("Details[ca_initialized] = %v, want false", result.Details["ca_initialized"])
		}
	})

	t.Run("CA not initialized returns degraded", func(t *testing.T) {
		ca := &healthCheckerMockCA{
			initialized: false,
			identity:    "test-ca",
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "CA configured but not fully initialized" {
			t.Errorf("Message = %v, want 'CA configured but not fully initialized'", result.Message)
		}
	})

	t.Run("TrustedRoot error returns degraded", func(t *testing.T) {
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCertErr: errors.New("certificate store unavailable"),
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "Failed to get trusted root certificate" {
			t.Errorf("Message = %v, want 'Failed to get trusted root certificate'", result.Message)
		}
	})

	t.Run("root cert not yet valid returns degraded", func(t *testing.T) {
		futureTime := time.Now().Add(24 * time.Hour)
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Future Root CA"},
				NotBefore: futureTime,
				NotAfter:  futureTime.Add(365 * 24 * time.Hour),
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "Root certificate not yet valid" {
			t.Errorf("Message = %v, want 'Root certificate not yet valid'", result.Message)
		}
	})

	t.Run("root cert expired returns unhealthy", func(t *testing.T) {
		pastTime := time.Now().Add(-365 * 24 * time.Hour)
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Expired Root CA"},
				NotBefore: pastTime.Add(-365 * 24 * time.Hour),
				NotAfter:  pastTime,
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "Root certificate has expired" {
			t.Errorf("Message = %v, want 'Root certificate has expired'", result.Message)
		}
	})

	t.Run("root cert expires soon returns degraded", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Expiring Root CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(15 * 24 * time.Hour), // Expires in 15 days
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "Root certificate expires soon" {
			t.Errorf("Message = %v, want 'Root certificate expires soon'", result.Message)
		}
		if result.Details["expires_in_days"] == nil {
			t.Error("Details[expires_in_days] should be set")
		}
	})

	t.Run("intermediate cert expired returns unhealthy", func(t *testing.T) {
		now := time.Now()
		pastTime := now.Add(-30 * 24 * time.Hour)
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Valid Root CA"},
				NotBefore: now.Add(-730 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
			intermediateCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Expired Intermediate CA"},
				NotBefore: pastTime.Add(-365 * 24 * time.Hour),
				NotAfter:  pastTime,
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "Intermediate certificate has expired" {
			t.Errorf("Message = %v, want 'Intermediate certificate has expired'", result.Message)
		}
	})

	t.Run("fully healthy CA returns healthy", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "production-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Production Root CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(3650 * 24 * time.Hour), // Valid for 10 years
			},
			intermediateCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Production Intermediate CA"},
				NotBefore: now.Add(-180 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "CA service is healthy" {
			t.Errorf("Message = %v, want 'CA service is healthy'", result.Message)
		}
		if result.Details["identity"] != "production-ca" {
			t.Errorf("Details[identity] = %v, want 'production-ca'", result.Details["identity"])
		}
		if result.Details["root_cn"] != "Production Root CA" {
			t.Errorf("Details[root_cn] = %v, want 'Production Root CA'", result.Details["root_cn"])
		}
		if result.Details["intermediate_cn"] != "Production Intermediate CA" {
			t.Errorf("Details[intermediate_cn] = %v, want 'Production Intermediate CA'", result.Details["intermediate_cn"])
		}
	})

	t.Run("healthy with nil root cert (no error)", func(t *testing.T) {
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert:    nil,
			rootCertErr: nil,
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		// With nil root cert and no error, should still be healthy
		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
	})

	t.Run("healthy with no intermediate (error getting intermediate)", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "root-only-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Root Only CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
			intermediateErr: errors.New("no intermediate configured"),
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
	})
}

// TestRESTServiceHealthChecker_CheckAllPaths tests all code paths in RESTServiceHealthChecker.Check
func TestRESTServiceHealthChecker_CheckAllPaths(t *testing.T) {
	t.Run("nil server returns unhealthy", func(t *testing.T) {
		checker := &RESTServiceHealthChecker{server: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "REST server reference is nil" {
			t.Errorf("Message = %v, want 'REST server reference is nil'", result.Message)
		}
	})

	t.Run("server not running returns unhealthy", func(t *testing.T) {
		config := &Config{
			RESTListenAddr: "127.0.0.1:8443",
			RESTConfig:     RESTServerConfig{},
		}
		server := &RESTServer{config: config}
		server.running.Store(false)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "REST server is not running" {
			t.Errorf("Message = %v, want 'REST server is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("server running returns healthy with all config details", func(t *testing.T) {
		config := &Config{
			RESTListenAddr:  "0.0.0.0:8443",
			RESTTLSCertFile: "/etc/ssl/cert.pem",
			RESTConfig: RESTServerConfig{
				EnableCORS:        true,
				EnableCompression: true,
			},
		}
		server := &RESTServer{config: config}
		server.running.Store(true)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "REST server is healthy" {
			t.Errorf("Message = %v, want 'REST server is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if result.Details["listen_addr"] != "0.0.0.0:8443" {
			t.Errorf("Details[listen_addr] = %v, want '0.0.0.0:8443'", result.Details["listen_addr"])
		}
		if result.Details["tls_enabled"] != true {
			t.Errorf("Details[tls_enabled] = %v, want true", result.Details["tls_enabled"])
		}
		if result.Details["cors_enabled"] != true {
			t.Errorf("Details[cors_enabled] = %v, want true", result.Details["cors_enabled"])
		}
		if result.Details["compression_enabled"] != true {
			t.Errorf("Details[compression_enabled] = %v, want true", result.Details["compression_enabled"])
		}
	})

	t.Run("server running without TLS shows tls_enabled false", func(t *testing.T) {
		config := &Config{
			RESTListenAddr:  "127.0.0.1:8080",
			RESTTLSCertFile: "",
			RESTConfig:      RESTServerConfig{},
		}
		server := &RESTServer{config: config}
		server.running.Store(true)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Details["tls_enabled"] != false {
			t.Errorf("Details[tls_enabled] = %v, want false", result.Details["tls_enabled"])
		}
	})
}

// TestHealthCheckerContext tests that health checkers handle context properly
func TestHealthCheckerContext(t *testing.T) {
	t.Run("ServiceHealthChecker works with cancelled context", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "ctx-test", running: true}
		checker := NewServiceHealthChecker(svc)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result := checker.Check(ctx)
		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
	})

	t.Run("KMSServiceHealthChecker works with cancelled context", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := NewKMSServiceHealthChecker(service)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result := checker.Check(ctx)
		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
	})

	t.Run("HealthCheckable service receives context", func(t *testing.T) {
		var receivedCtx context.Context
		svc := &healthCheckerMockHealthCheckableService{
			healthCheckerMockManagedService: healthCheckerMockManagedService{
				name:    "ctx-receiver",
				running: true,
			},
		}
		svc.healthFunc = func(ctx context.Context) error {
			receivedCtx = ctx
			return nil
		}

		checker := NewServiceHealthChecker(svc)
		testCtx := context.WithValue(context.Background(), healthCheckerContextKey("test-key"), "test-value")
		checker.Check(testCtx)

		if receivedCtx == nil {
			t.Error("HealthCheck should receive context")
		}
		if receivedCtx.Value(healthCheckerContextKey("test-key")) != "test-value" {
			t.Error("HealthCheck should receive the same context")
		}
	})
}

// TestHealthCheckerConcurrentSafety tests thread safety of health checkers
func TestHealthCheckerConcurrentSafety(t *testing.T) {
	t.Run("ServiceHealthChecker concurrent access", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "concurrent", running: true}
		checker := NewServiceHealthChecker(svc)

		done := make(chan bool, 100)
		for i := 0; i < 100; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 100; i++ {
			<-done
		}
	})

	t.Run("KMSServiceHealthChecker concurrent access", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := NewKMSServiceHealthChecker(service)

		done := make(chan bool, 100)
		for i := 0; i < 100; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 100; i++ {
			<-done
		}
	})

	t.Run("SDNServiceHealthChecker concurrent access", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
		}
		checker := NewSDNServiceHealthChecker(service)

		done := make(chan bool, 100)
		for i := 0; i < 100; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 100; i++ {
			<-done
		}
	})

	t.Run("RESTServiceHealthChecker concurrent access", func(t *testing.T) {
		config := &Config{
			RESTListenAddr: "127.0.0.1:8443",
			RESTConfig:     RESTServerConfig{},
		}
		server := &RESTServer{config: config}
		server.running.Store(true)
		checker := NewRESTServiceHealthChecker(server)

		done := make(chan bool, 100)
		for i := 0; i < 100; i++ {
			go func() {
				_ = checker.Check(context.Background())
				done <- true
			}()
		}

		for i := 0; i < 100; i++ {
			<-done
		}
	})
}

// TestHealthCheckerComponentHealthStructure verifies the ComponentHealth struct is properly populated
func TestHealthCheckerComponentHealthStructure(t *testing.T) {
	t.Run("all fields are populated for healthy service", func(t *testing.T) {
		svc := &healthCheckerMockManagedService{name: "complete-test", running: true}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		// Verify all fields
		if result.Name != "complete-test" {
			t.Errorf("Name = %v, want 'complete-test'", result.Name)
		}
		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message == "" {
			t.Error("Message should not be empty")
		}
		if result.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
		if result.Details == nil {
			t.Error("Details should not be nil")
		}
	})

	t.Run("all fields are populated for unhealthy service", func(t *testing.T) {
		checker := &ServiceHealthChecker{service: nil}

		result := checker.Check(context.Background())

		if result.Name != "unknown" {
			t.Errorf("Name = %v, want 'unknown'", result.Name)
		}
		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message == "" {
			t.Error("Message should not be empty")
		}
		if result.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
		if result.Details == nil {
			t.Error("Details should not be nil")
		}
	})

	t.Run("all fields are populated for degraded service", func(t *testing.T) {
		svc := &healthCheckerMockHealthCheckableService{
			healthCheckerMockManagedService: healthCheckerMockManagedService{
				name:      "degraded-test",
				running:   true,
				healthErr: errors.New("partial failure"),
			},
		}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Name != "degraded-test" {
			t.Errorf("Name = %v, want 'degraded-test'", result.Name)
		}
		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message == "" {
			t.Error("Message should not be empty")
		}
		if result.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
		if result.Details == nil {
			t.Error("Details should not be nil")
		}
	})
}

// TestHealthCheckerNameMethod verifies the Name() method for all checkers
func TestHealthCheckerNameMethod(t *testing.T) {
	testCases := []struct {
		name     string
		checker  health.HealthChecker
		wantName string
	}{
		{
			name:     "ServiceHealthChecker with service",
			checker:  NewServiceHealthChecker(&healthCheckerMockManagedService{name: "my-service"}),
			wantName: "my-service",
		},
		{
			name:     "ServiceHealthChecker with nil service",
			checker:  &ServiceHealthChecker{service: nil},
			wantName: "unknown",
		},
		{
			name:     "KMSServiceHealthChecker",
			checker:  &KMSServiceHealthChecker{service: nil},
			wantName: "kms",
		},
		{
			name:     "IAMServiceHealthChecker",
			checker:  &IAMServiceHealthChecker{service: nil},
			wantName: "iam",
		},
		{
			name:     "TenantServiceHealthChecker",
			checker:  &TenantServiceHealthChecker{service: nil},
			wantName: "tenant",
		},
		{
			name:     "SDNServiceHealthChecker",
			checker:  &SDNServiceHealthChecker{service: nil},
			wantName: "sdn",
		},
		{
			name:     "CAServiceHealthChecker",
			checker:  &CAServiceHealthChecker{service: nil},
			wantName: "ca",
		},
		{
			name:     "QUICServerHealthChecker",
			checker:  &QUICServerHealthChecker{server: nil},
			wantName: "quic",
		},
		{
			name:     "RESTServiceHealthChecker",
			checker:  &RESTServiceHealthChecker{server: nil},
			wantName: "rest",
		},
		{
			name:     "MCPServiceHealthChecker",
			checker:  &MCPServiceHealthChecker{server: nil},
			wantName: "mcp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.checker.Name(); got != tc.wantName {
				t.Errorf("Name() = %v, want %v", got, tc.wantName)
			}
		})
	}
}
