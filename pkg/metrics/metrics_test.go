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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Success(t *testing.T) {
	config := DefaultConfig()
	config.Namespace = "test_platform"

	m, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, m)

	// Verify SDN metrics are initialized
	assert.NotNil(t, m.SDNPortStateChanges)
	assert.NotNil(t, m.SDNFlowInstallations)
	assert.NotNil(t, m.SDNFlowDeletions)
	assert.NotNil(t, m.SDNFlowErrors)
	assert.NotNil(t, m.SDNFlowDuration)
	assert.NotNil(t, m.SDNActivePorts)
	assert.NotNil(t, m.SDNActiveFlows)
	assert.NotNil(t, m.SDNPolicyEvaluations)
	assert.NotNil(t, m.SDNAuthAttempts)
	assert.NotNil(t, m.SDNQuarantinedPorts)

	// Verify certificate metrics are initialized
	assert.NotNil(t, m.CertEnrollments)
	assert.NotNil(t, m.CertRevocations)
	assert.NotNil(t, m.CertRenewals)
	assert.NotNil(t, m.CertValidations)
	assert.NotNil(t, m.CertOperationDuration)
	assert.NotNil(t, m.CertExpirations)
	assert.NotNil(t, m.CertActiveCount)
	assert.NotNil(t, m.CertIssuanceErrors)
	assert.NotNil(t, m.CertChainDepth)

	// Verify API metrics are initialized
	assert.NotNil(t, m.HTTPRequests)
	assert.NotNil(t, m.HTTPRequestDuration)
	assert.NotNil(t, m.HTTPRequestSize)
	assert.NotNil(t, m.HTTPResponseSize)
	assert.NotNil(t, m.HTTPActiveRequests)
	assert.NotNil(t, m.HTTPErrors)
	assert.NotNil(t, m.GRPCRequests)
	assert.NotNil(t, m.GRPCRequestDuration)
	assert.NotNil(t, m.GRPCStreamMessages)
	assert.NotNil(t, m.GRPCActiveStreams)

	// Verify system metrics are initialized
	assert.NotNil(t, m.DaemonUptime)
	assert.NotNil(t, m.DaemonStartTime)
	assert.NotNil(t, m.ServiceStatus)
	assert.NotNil(t, m.GoroutineCount)
	assert.NotNil(t, m.MemoryUsage)
	assert.NotNil(t, m.CPUUsage)
	assert.NotNil(t, m.OpenFileDescriptors)
	assert.NotNil(t, m.DatabaseConnections)
	assert.NotNil(t, m.CacheHitRate)
	assert.NotNil(t, m.ErrorRate)

	// Verify TPM metrics are initialized
	assert.NotNil(t, m.TPMOperations)
	assert.NotNil(t, m.TPMOperationDuration)
	assert.NotNil(t, m.TPMErrors)
	assert.NotNil(t, m.TPMQuoteVerifications)

	// Verify storage metrics are initialized
	assert.NotNil(t, m.StorageOperations)
	assert.NotNil(t, m.StorageSize)
	assert.NotNil(t, m.StorageLatency)
}

func TestNew_NilConfig(t *testing.T) {
	// Create new registry to avoid conflicts
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	m, err := New(nil)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.NotNil(t, m.config)
}

func TestNew_DisabledMetrics(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = false

	m, err := New(config)
	assert.Error(t, err)
	assert.Nil(t, m)

	var metricsErr ErrMetricsNotEnabled
	assert.ErrorAs(t, err, &metricsErr)
}

func TestNew_InvalidConfig(t *testing.T) {
	config := DefaultConfig()
	config.Namespace = "" // Invalid

	m, err := New(config)
	assert.Error(t, err)
	assert.Nil(t, m)
}

func TestSDNMetrics_Recording(t *testing.T) {
	// Create new registry to avoid conflicts
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	config := DefaultConfig()
	config.Namespace = "test_sdn"

	m, err := New(config)
	require.NoError(t, err)

	// Test counter metrics
	m.SDNPortStateChanges.WithLabelValues("port1", "unauthorized", "authorized", "br0").Inc()
	m.SDNFlowInstallations.WithLabelValues("br0", "0", "100", "success").Add(5)
	m.SDNFlowDeletions.WithLabelValues("br0", "0", "success").Inc()
	m.SDNFlowErrors.WithLabelValues("install", "timeout", "br0").Inc()

	// Test histogram metrics
	m.SDNFlowDuration.WithLabelValues("install", "br0").Observe(0.125)
	m.SDNFlowDuration.WithLabelValues("delete", "br0").Observe(0.050)

	// Test gauge metrics
	m.SDNActivePorts.Set(10)
	m.SDNActiveFlows.Set(250)
	m.SDNQuarantinedPorts.Set(2)

	// Test policy evaluation metrics
	m.SDNPolicyEvaluations.WithLabelValues("port1", "allow", "valid_cert").Inc()
	m.SDNAuthAttempts.WithLabelValues("port1", "success", "certificate").Inc()

	// Verify metrics were recorded (by checking they don't panic)
	// Full verification would require scraping the registry
}

func TestCertificateMetrics_Recording(t *testing.T) {
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	config := DefaultConfig()
	config.Namespace = "test_cert"

	m, err := New(config)
	require.NoError(t, err)

	// Test enrollment metrics
	m.CertEnrollments.WithLabelValues("root-ca", "tls-server", "success").Inc()
	m.CertEnrollments.WithLabelValues("root-ca", "tls-client", "failure").Inc()

	// Test revocation metrics
	m.CertRevocations.WithLabelValues("root-ca", "key_compromise").Inc()
	m.CertRevocations.WithLabelValues("root-ca", "superseded").Inc()

	// Test renewal metrics
	m.CertRenewals.WithLabelValues("root-ca", "success").Add(3)

	// Test validation metrics
	m.CertValidations.WithLabelValues("root-ca", "valid").Add(100)
	m.CertValidations.WithLabelValues("root-ca", "expired").Add(5)

	// Test operation duration
	m.CertOperationDuration.WithLabelValues("enroll", "root-ca").Observe(2.5)
	m.CertOperationDuration.WithLabelValues("revoke", "root-ca").Observe(0.5)

	// Test gauge metrics
	m.CertExpirations.Set(15)
	m.CertActiveCount.WithLabelValues("root-ca", "tls-server").Set(50)
	m.CertActiveCount.WithLabelValues("root-ca", "tls-client").Set(100)

	// Test error metrics
	m.CertIssuanceErrors.WithLabelValues("root-ca", "validation_failed").Inc()
	m.CertIssuanceErrors.WithLabelValues("root-ca", "policy_denied").Inc()

	// Test chain depth
	m.CertChainDepth.WithLabelValues("root-ca").Observe(3)
	m.CertChainDepth.WithLabelValues("intermediate-ca").Observe(2)
}

func TestAPIMetrics_Recording(t *testing.T) {
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	config := DefaultConfig()
	config.Namespace = "test_api"

	m, err := New(config)
	require.NoError(t, err)

	// Test HTTP metrics
	m.HTTPRequests.WithLabelValues("GET", "/api/v1/status", "200").Inc()
	m.HTTPRequests.WithLabelValues("POST", "/api/v1/enroll", "201").Inc()
	m.HTTPRequests.WithLabelValues("GET", "/api/v1/cert", "404").Inc()

	m.HTTPRequestDuration.WithLabelValues("GET", "/api/v1/status").Observe(0.025)
	m.HTTPRequestDuration.WithLabelValues("POST", "/api/v1/enroll").Observe(1.5)

	m.HTTPRequestSize.WithLabelValues("POST", "/api/v1/enroll").Observe(2048)
	m.HTTPResponseSize.WithLabelValues("POST", "/api/v1/enroll").Observe(4096)

	m.HTTPActiveRequests.Set(5)

	m.HTTPErrors.WithLabelValues("GET", "/api/v1/cert", "not_found").Inc()
	m.HTTPErrors.WithLabelValues("POST", "/api/v1/enroll", "validation_error").Inc()

	// Test gRPC metrics
	m.GRPCRequests.WithLabelValues("PlatformDaemon", "GetStatus", "OK").Inc()
	m.GRPCRequests.WithLabelValues("PlatformDaemon", "StartService", "FAILED_PRECONDITION").Inc()

	m.GRPCRequestDuration.WithLabelValues("PlatformDaemon", "GetStatus").Observe(0.010)
	m.GRPCRequestDuration.WithLabelValues("PlatformDaemon", "StartService").Observe(0.500)

	m.GRPCStreamMessages.WithLabelValues("PlatformDaemon", "StreamLogs", "sent").Add(100)
	m.GRPCStreamMessages.WithLabelValues("PlatformDaemon", "StreamLogs", "received").Add(50)

	m.GRPCActiveStreams.Set(3)
}

func TestSystemMetrics_Recording(t *testing.T) {
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	config := DefaultConfig()
	config.Namespace = "test_system"

	m, err := New(config)
	require.NoError(t, err)

	// Test system health metrics
	m.DaemonUptime.Set(3600.5)
	m.DaemonStartTime.Set(1640000000)

	m.ServiceStatus.WithLabelValues("api").Set(1)
	m.ServiceStatus.WithLabelValues("sdn").Set(1)
	m.ServiceStatus.WithLabelValues("dns").Set(0)

	m.GoroutineCount.Set(42)

	m.MemoryUsage.WithLabelValues("alloc").Set(1048576)
	m.MemoryUsage.WithLabelValues("sys").Set(4194304)

	m.CPUUsage.Set(25.5)
	m.OpenFileDescriptors.Set(128)

	m.DatabaseConnections.WithLabelValues("kvstore", "active").Set(10)
	m.DatabaseConnections.WithLabelValues("kvstore", "idle").Set(5)

	m.CacheHitRate.WithLabelValues("cert_cache", "hit").Add(950)
	m.CacheHitRate.WithLabelValues("cert_cache", "miss").Add(50)

	m.ErrorRate.WithLabelValues("api", "validation_error").Inc()
	m.ErrorRate.WithLabelValues("sdn", "flow_installation_error").Inc()
}

func TestTPMMetrics_Recording(t *testing.T) {
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	config := DefaultConfig()
	config.Namespace = "test_tpm"

	m, err := New(config)
	require.NoError(t, err)

	// Test TPM operation metrics
	m.TPMOperations.WithLabelValues("seal", "success").Add(10)
	m.TPMOperations.WithLabelValues("unseal", "success").Add(10)
	m.TPMOperations.WithLabelValues("quote", "success").Add(5)
	m.TPMOperations.WithLabelValues("seal", "failure").Inc()

	m.TPMOperationDuration.WithLabelValues("seal").Observe(0.150)
	m.TPMOperationDuration.WithLabelValues("unseal").Observe(0.125)
	m.TPMOperationDuration.WithLabelValues("quote").Observe(0.200)

	m.TPMErrors.WithLabelValues("seal", "pcr_mismatch").Inc()
	m.TPMErrors.WithLabelValues("quote", "verification_failed").Inc()

	m.TPMQuoteVerifications.WithLabelValues("success").Add(45)
	m.TPMQuoteVerifications.WithLabelValues("failure").Add(5)
}

func TestStorageMetrics_Recording(t *testing.T) {
	registry := prometheus.NewRegistry()
	oldDefault := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	defer func() {
		prometheus.DefaultRegisterer = oldDefault
	}()

	config := DefaultConfig()
	config.Namespace = "test_storage"

	m, err := New(config)
	require.NoError(t, err)

	// Test storage operation metrics
	m.StorageOperations.WithLabelValues("kvstore", "get", "success").Add(1000)
	m.StorageOperations.WithLabelValues("kvstore", "put", "success").Add(500)
	m.StorageOperations.WithLabelValues("kvstore", "delete", "success").Add(100)
	m.StorageOperations.WithLabelValues("kvstore", "get", "not_found").Add(50)

	m.StorageSize.WithLabelValues("kvstore", "data").Set(10485760)
	m.StorageSize.WithLabelValues("objstore", "data").Set(104857600)

	m.StorageLatency.WithLabelValues("kvstore", "get").Observe(0.001)
	m.StorageLatency.WithLabelValues("kvstore", "put").Observe(0.005)
	m.StorageLatency.WithLabelValues("objstore", "get").Observe(0.010)
}

func TestMetrics_Config(t *testing.T) {
	config := DefaultConfig()
	config.Namespace = "test_config"

	m, err := New(config)
	require.NoError(t, err)

	returnedConfig := m.Config()
	assert.Equal(t, config.Namespace, returnedConfig.Namespace)
	assert.Equal(t, config.Port, returnedConfig.Port)
}

func TestMetrics_MetricName(t *testing.T) {
	config := DefaultConfig()
	config.Namespace = "platform"

	m, err := New(config)
	require.NoError(t, err)

	tests := []struct {
		name      string
		subsystem string
		metric    string
		expected  string
	}{
		{
			name:      "with subsystem",
			subsystem: "api",
			metric:    "requests_total",
			expected:  "platform_api_requests_total",
		},
		{
			name:      "without subsystem",
			subsystem: "",
			metric:    "uptime",
			expected:  "platform_uptime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MetricName(tt.subsystem, tt.metric)
			assert.Equal(t, tt.expected, result)
		})
	}
}
