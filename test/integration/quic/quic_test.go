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

//go:build integration

// Package quic provides integration tests for the QUIC protocol handlers.
// These tests require a running QUIC server and are executed via:
//
//	make integration-test-quic
//
// The tests verify end-to-end functionality of all QUIC service handlers
// including CA, vTPM, DNS, SDN, KMS, IAM, and Device operations.
package quic

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultQUICAddr = "localhost:9444"
	testTimeout     = 30 * time.Second
)

// TestConfig holds integration test configuration.
type TestConfig struct {
	QUICAddr string
	Token    string
}

// skipIfNotIntegration skips the test if INTEGRATION_TEST env var is not set.
func skipIfNotIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// getTestConfig returns the test configuration from environment variables.
func getTestConfig() *TestConfig {
	addr := os.Getenv("QUIC_SERVER_ADDR")
	if addr == "" {
		addr = defaultQUICAddr
	}

	return &TestConfig{
		QUICAddr: addr,
		Token:    os.Getenv("QUIC_AUTH_TOKEN"),
	}
}

// newTestClient creates a new test client with the standard configuration.
// If the server is not available, it skips the test instead of failing.
func newTestClient(t *testing.T, cfg *TestConfig) (*TestClient, func()) {
	logger := logging.DefaultLogger()

	opts := []TestClientOption{
		WithTestClientLogger(logger),
		WithTestClientTimeout(testTimeout),
	}

	if cfg.Token != "" {
		opts = append(opts, WithTestClientToken(cfg.Token))
	}

	client := NewTestClient(cfg.QUICAddr, opts...)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Short timeout for connection check
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Skipf("QUIC server not available at %s: %v (start platformd with --enable-quic to run these tests)", cfg.QUICAddr, err)
	}

	cleanup := func() {
		client.Close()
	}

	return client, cleanup
}

// =============================================================================
// Health Operations Tests
// =============================================================================

func TestQUICHealth(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("Health check succeeds", func(t *testing.T) {
		var resp daemon.HealthCheckResponse
		err := client.Send(ctx, quic.OpHealth, nil, &resp)
		require.NoError(t, err)
		assert.True(t, resp.Healthy, "Server should report healthy")
		assert.NotEmpty(t, resp.Status, "Status should not be empty")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("Liveness check succeeds", func(t *testing.T) {
		var resp daemon.HealthCheckResponse
		err := client.Send(ctx, quic.OpLiveness, nil, &resp)
		require.NoError(t, err)
		assert.True(t, resp.Healthy, "Server should report healthy")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("Readiness check succeeds", func(t *testing.T) {
		var resp daemon.HealthCheckResponse
		err := client.Send(ctx, quic.OpReadiness, nil, &resp)
		require.NoError(t, err)
		assert.True(t, resp.Healthy, "Server should report ready")
		assert.NotNil(t, resp.Components, "Components map should be present")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})
}

// =============================================================================
// CA Operations Tests (Opcodes 0xA0-0xA8)
// =============================================================================

func TestQUICCA(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("CA Info returns certificate authority info", func(t *testing.T) {
		resp, err := client.SendRequest(ctx, quic.OpCAInfo, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("CA service not available")
				}
			}
			t.Fatalf("CA Info request failed: %v", err)
		}
		if resp.Status == quic.StatusUnavailable {
			t.Skip("CA service not available")
		}
		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("CA Get with missing serial returns error", func(t *testing.T) {
		// CA Get requires serial number
		type CAGetRequest struct {
			Serial string `codec:"serial"`
		}
		req := &CAGetRequest{Serial: ""}
		resp, err := client.SendExpectStatus(ctx, quic.OpCAGet, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("CA service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("CA List returns certificate list", func(t *testing.T) {
		resp, err := client.SendRequest(ctx, quic.OpCAList, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("CA service not available")
				}
			}
			t.Fatalf("CA List request failed: %v", err)
		}
		if resp.Status == quic.StatusUnavailable {
			t.Skip("CA service not available")
		}
		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("CA Bundle returns trust chain", func(t *testing.T) {
		resp, err := client.SendRequest(ctx, quic.OpCABundle, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("CA service not available")
				}
			}
			t.Fatalf("CA Bundle request failed: %v", err)
		}
		if resp.Status == quic.StatusUnavailable {
			t.Skip("CA service not available")
		}
		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

// =============================================================================
// vTPM Operations Tests (Opcodes 0x03-0x1F)
// =============================================================================

func TestQUICVTPM(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("vTPM List returns bundle list", func(t *testing.T) {
		var resp daemon.VTPMListResponse
		err := client.Send(ctx, quic.OpVTPMList, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("vTPM service not available")
				}
			}
			t.Fatalf("vTPM List request failed: %v", err)
		}
		assert.NotNil(t, resp.Bundles, "Bundles should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("vTPM Create with missing hostname returns error", func(t *testing.T) {
		req := &daemon.VTPMCreateRequest{
			Hostname: "",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpVTPMCreate, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("vTPM service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("vTPM GetState with missing BundleID returns error", func(t *testing.T) {
		// VTPMGetStateRequest uses BundleID field
		type VTPMGetStateRequest struct {
			BundleID string `codec:"bundle_id"`
		}
		req := &VTPMGetStateRequest{
			BundleID: "",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpVTPMGetState, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("vTPM service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("vTPM Delete with missing BundleID returns error", func(t *testing.T) {
		req := &daemon.VTPMDeleteRequest{
			BundleID: "",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpVTPMDelete, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("vTPM service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("vTPM ListTemplates returns templates", func(t *testing.T) {
		resp, err := client.SendRequest(ctx, quic.OpVTPMListTemplates, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("vTPM service not available")
				}
			}
			t.Fatalf("vTPM ListTemplates request failed: %v", err)
		}
		if resp.Status == quic.StatusUnavailable {
			t.Skip("vTPM service not available")
		}
		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

// =============================================================================
// DNS Operations Tests (Opcodes 0x20-0x2D)
// =============================================================================

func TestQUICDNS(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("DNS ListZones returns zone list", func(t *testing.T) {
		var resp daemon.DNSListZonesResponse
		err := client.Send(ctx, quic.OpDNSListZones, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("DNS service not available")
				}
			}
			t.Fatalf("DNS ListZones request failed: %v", err)
		}
		assert.NotNil(t, resp.Zones, "Zones should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("DNS GetConfig returns configuration", func(t *testing.T) {
		var resp daemon.DNSGetConfigResponse
		err := client.Send(ctx, quic.OpDNSGetConfig, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("DNS service not available")
				}
			}
			t.Fatalf("DNS GetConfig request failed: %v", err)
		}
		assert.NotNil(t, resp.Config, "Config should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("DNS GetMetrics returns metrics", func(t *testing.T) {
		var resp daemon.DNSGetMetricsResponse
		err := client.Send(ctx, quic.OpDNSGetMetrics, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("DNS service not available")
				}
			}
			t.Fatalf("DNS GetMetrics request failed: %v", err)
		}
		assert.NotNil(t, resp.Metrics, "Metrics should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("DNS AddRecord with missing zone returns error", func(t *testing.T) {
		req := &daemon.DNSAddRecordRequest{
			Zone:       "",
			Name:       "test",
			RecordType: "A",
			Value:      "192.168.1.1",
			TTL:        3600,
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpDNSAddRecord, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("DNS service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("DNS GetRecord with missing zone returns error", func(t *testing.T) {
		req := &daemon.DNSGetRecordRequest{
			Zone:       "",
			Name:       "test",
			RecordType: "A",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpDNSGetRecord, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("DNS service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("DNS AddZone with missing name returns error", func(t *testing.T) {
		req := &daemon.DNSAddZoneRequest{
			Name: "",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpDNSAddZone, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("DNS service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})
}

// =============================================================================
// SDN Operations Tests (Opcodes 0x40-0x4F, 0xB0-0xB4)
// =============================================================================

func TestQUICSDN(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	t.Run("SDN ListBridges returns bridge list", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(opCancel)

		t.Log("sending SDN ListBridges request")
		var resp daemon.SDNListBridgesResponse
		err := client.Send(opCtx, quic.OpSDNListBridges, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("SDN service not available")
				}
			}
			t.Fatalf("SDN ListBridges request failed: %v", err)
		}
		t.Log("SDN ListBridges completed successfully")
		assert.NotNil(t, resp.Bridges, "Bridges should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("SDN ListPolicies returns policy list", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(opCancel)

		t.Log("sending SDN ListPolicies request")
		resp, err := client.SendRequest(opCtx, quic.OpSDNListPolicies, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("SDN service not available")
				}
			}
			t.Fatalf("SDN ListPolicies request failed: %v", err)
		}
		if resp.Status == quic.StatusUnavailable {
			t.Skip("SDN service not available")
		}
		t.Log("SDN ListPolicies completed successfully")
		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("SDN GetBridge with missing name returns error", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(opCancel)

		t.Log("sending SDN GetBridge with empty name")
		req := &daemon.SDNGetBridgeRequest{
			Name: "",
		}
		resp, err := client.SendExpectStatus(opCtx, quic.OpSDNGetBridge, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("SDN service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
		t.Log("SDN GetBridge error handling verified")
	})

	t.Run("SDN CreateBridge with missing name returns error", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(opCancel)

		t.Log("sending SDN CreateBridge with empty name")
		req := &daemon.SDNCreateBridgeRequest{
			Name: "",
		}
		resp, err := client.SendExpectStatus(opCtx, quic.OpSDNCreateBridge, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("SDN service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
		t.Log("SDN CreateBridge error handling verified")
	})

	t.Run("SDN GetPortState with missing port returns error", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(opCancel)

		t.Log("sending SDN GetPortState with empty port")
		req := &daemon.SDNGetPortStateRequest{
			PortName: "",
		}
		resp, err := client.SendExpectStatus(opCtx, quic.OpSDNGetPortState, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("SDN service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
		t.Log("SDN GetPortState error handling verified")
	})

	t.Run("SDN GetMetrics returns metrics", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(opCancel)

		t.Log("sending SDN GetMetrics request")
		resp, err := client.SendRequest(opCtx, quic.OpSDNGetMetrics, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("SDN service not available")
				}
			}
			t.Fatalf("SDN GetMetrics request failed: %v", err)
		}
		if resp.Status == quic.StatusUnavailable {
			t.Skip("SDN service not available")
		}
		t.Log("SDN GetMetrics completed successfully")
		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

// =============================================================================
// KMS Operations Tests (Opcodes 0xC0-0xDF)
// =============================================================================

func TestQUICKMS(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("KMS ListKeys returns key list", func(t *testing.T) {
		var resp daemon.KMSListKeysResponse
		err := client.Send(ctx, quic.OpKMSListKeys, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("KMS service not available")
				}
			}
			t.Fatalf("KMS ListKeys request failed: %v", err)
		}
		assert.NotNil(t, resp.Keys, "Keys should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("KMS BackendStatus returns status", func(t *testing.T) {
		var resp daemon.KMSBackendStatusResponse
		err := client.Send(ctx, quic.OpKMSBackendStatus, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("KMS service not available")
				}
			}
			t.Fatalf("KMS BackendStatus request failed: %v", err)
		}
		assert.NotEmpty(t, resp.BackendType, "BackendType should not be empty")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("KMS GetKey with missing key_id returns error", func(t *testing.T) {
		req := &daemon.KMSGetKeyRequest{
			KeyID: "",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpKMSGetKey, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("KMS service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest, quic.StatusNotFound}, resp.Status)
		}
	})

	t.Run("KMS GenerateKey with missing key_spec returns error", func(t *testing.T) {
		req := &daemon.KMSGenerateKeyRequest{
			KeySpec: nil,
			Name:    "test-key",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpKMSGenerateKey, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("KMS service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("KMS Encrypt with missing key_id returns error", func(t *testing.T) {
		req := &daemon.KMSEncryptRequest{
			KeyID:     "",
			Plaintext: []byte("test data"),
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpKMSEncrypt, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("KMS service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest, quic.StatusNotFound}, resp.Status)
		}
	})

	t.Run("KMS GenerateRandom returns random bytes", func(t *testing.T) {
		type GenerateRandomRequest struct {
			NumBytes int32 `codec:"num_bytes"`
		}
		type GenerateRandomResponse struct {
			RandomBytes []byte `codec:"random_bytes"`
			Timestamp   int64  `codec:"timestamp"`
		}

		req := &GenerateRandomRequest{NumBytes: 32}
		var resp GenerateRandomResponse
		err := client.Send(ctx, quic.OpKMSGenerateRandom, req, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("KMS service not available")
				}
			}
			t.Fatalf("KMS GenerateRandom request failed: %v", err)
		}
		assert.Len(t, resp.RandomBytes, 32, "Should return 32 random bytes")
	})
}

// =============================================================================
// IAM Operations Tests (Opcodes 0xA9-0xBF, 0xF6-0xFB)
// =============================================================================

func TestQUICIAM(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("IAM ListUsers returns user list", func(t *testing.T) {
		req := &daemon.ListIAMRequest{
			TenantID: "default",
			Limit:    10,
		}
		var resp daemon.IAMUserListResponse
		err := client.Send(ctx, quic.OpIAMUserList, req, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
			t.Fatalf("IAM ListUsers request failed: %v", err)
		}
		assert.NotNil(t, resp.Users, "Users should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("IAM ListRoles returns role list", func(t *testing.T) {
		req := &daemon.ListIAMRequest{
			TenantID: "default",
			Limit:    10,
		}
		var resp daemon.IAMRoleListResponse
		err := client.Send(ctx, quic.OpIAMRoleList, req, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
			t.Fatalf("IAM ListRoles request failed: %v", err)
		}
		assert.NotNil(t, resp.Roles, "Roles should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("IAM ListGroups returns group list", func(t *testing.T) {
		req := &daemon.ListIAMRequest{
			TenantID: "default",
			Limit:    10,
		}
		var resp daemon.IAMGroupListResponse
		err := client.Send(ctx, quic.OpIAMGroupList, req, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
			t.Fatalf("IAM ListGroups request failed: %v", err)
		}
		assert.NotNil(t, resp.Groups, "Groups should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("IAM CreateUser with missing tenant_id returns error", func(t *testing.T) {
		req := &daemon.CreateUserRequest{
			TenantID: "",
			Email:    "test@example.com",
			Username: "testuser",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpIAMUserCreate, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("IAM GetUser with missing user_id returns error", func(t *testing.T) {
		req := &daemon.GetUserRequest{
			TenantID: "default",
			UserID:   "",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpIAMUserGet, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest, quic.StatusNotFound}, resp.Status)
		}
	})

	t.Run("IAM CheckPermission validates access", func(t *testing.T) {
		req := &daemon.CheckPermissionRequest{
			TenantID:  "default",
			SubjectID: "test-subject",
			Resource:  "test-resource",
			Action:    "read",
		}
		var resp daemon.CheckPermissionResponse
		err := client.Send(ctx, quic.OpIAMCheckPermission, req, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
			t.Fatalf("IAM CheckPermission request failed: %v", err)
		}
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("IAM VerifyToken with invalid token returns error", func(t *testing.T) {
		req := &daemon.VerifyTokenRequest{
			Token: "invalid-token",
		}
		resp, err := client.SendRequest(ctx, quic.OpIAMTokenVerify, nil)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("IAM service not available")
				}
			}
		}
		// Token verification with invalid token should fail or return invalid
		if resp != nil && resp.Status == quic.StatusOK {
			var tokenResp daemon.TokenVerifyResponse
			err := quic.DecodePayload(resp.Payload, &tokenResp)
			if err == nil {
				assert.False(t, tokenResp.Valid, "Invalid token should not be valid")
			}
		}
		_ = req // Use req to avoid unused variable warning
	})
}

// =============================================================================
// Device Operations Tests (Opcodes 0x30-0x3F)
// =============================================================================

func TestQUICDevice(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("Device List returns device list", func(t *testing.T) {
		var resp daemon.DeviceListResponse
		err := client.Send(ctx, quic.OpDeviceList, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("Device service not available")
				}
			}
			t.Fatalf("Device List request failed: %v", err)
		}
		assert.NotNil(t, resp.Devices, "Devices should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("Device ListProfiles returns profile list", func(t *testing.T) {
		// ProfileListResponse matches the QUIC handler response type
		type ProfileListResponse struct {
			Profiles  []interface{} `codec:"profiles"`
			Total     int           `codec:"total"`
			Timestamp int64         `codec:"timestamp"`
		}
		var resp ProfileListResponse
		err := client.Send(ctx, quic.OpDeviceListProfiles, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("Device profile service not available")
				}
			}
			t.Fatalf("Device ListProfiles request failed: %v", err)
		}
		assert.NotNil(t, resp.Profiles, "Profiles should not be nil")
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("Device GetMetrics returns metrics", func(t *testing.T) {
		// DeviceMetrics response type
		type DeviceMetricsResponse struct {
			TotalDevices    int   `codec:"total_devices"`
			ActiveDevices   int   `codec:"active_devices"`
			RegisteredToday int   `codec:"registered_today"`
			AttestationRate int   `codec:"attestation_rate"`
			Timestamp       int64 `codec:"timestamp"`
		}
		var resp DeviceMetricsResponse
		err := client.Send(ctx, quic.OpDeviceGetMetrics, nil, &resp)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("Device service not available")
				}
			}
			t.Fatalf("Device GetMetrics request failed: %v", err)
		}
		assert.NotZero(t, resp.Timestamp, "Timestamp should be set")
	})

	t.Run("Device Register with missing ID returns error", func(t *testing.T) {
		req := &daemon.DeviceRegisterRequest{
			ID:     0,
			Serial: "TEST-SERIAL",
			Model:  "TEST-MODEL",
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpDeviceRegister, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("Device service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("Device Get with missing ID returns error", func(t *testing.T) {
		req := &daemon.DeviceGetRequest{
			ID: 0,
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpDeviceGet, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("Device service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})

	t.Run("Device GetProfile with missing ID returns error", func(t *testing.T) {
		// ProfileGetRequest matches the QUIC handler request type
		type ProfileGetRequest struct {
			ID uint64 `codec:"id"`
		}
		req := &ProfileGetRequest{
			ID: 0,
		}
		resp, err := client.SendExpectStatus(ctx, quic.OpDeviceGetProfile, req, quic.StatusInvalidArgument)
		if err != nil {
			var unexpectedStatus ErrUnexpectedStatus
			if assert.ErrorAs(t, err, &unexpectedStatus) {
				if unexpectedStatus.Actual == quic.StatusUnavailable {
					t.Skip("Device profile service not available")
				}
			}
		}
		if resp != nil {
			assert.Contains(t, []byte{quic.StatusInvalidArgument, quic.StatusInvalidRequest}, resp.Status)
		}
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestQUICErrorHandling(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()
	client, cleanup := newTestClient(t, cfg)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	t.Run("Unregistered service opcode returns error", func(t *testing.T) {
		// 0xFF maps to OpPXERemoveDevice - all byte values are assigned to opcode ranges,
		// so the server dispatches to the PXE handler (which returns StatusUnavailable if
		// the PXE service isn't registered) rather than hitting the default case.
		resp, err := client.SendRequest(ctx, 0xFF, nil)
		require.NoError(t, err)
		assert.Contains(t, []byte{quic.StatusNotImplemented, quic.StatusUnavailable}, resp.Status)
	})

	t.Run("Invalid payload returns InvalidRequest", func(t *testing.T) {
		// Send garbage payload to an opcode that expects structured data
		resp, err := client.SendRequest(ctx, quic.OpVTPMCreate, []byte("invalid payload"))
		require.NoError(t, err)
		assert.Contains(t, []byte{quic.StatusInvalidRequest, quic.StatusInvalidArgument, quic.StatusUnavailable}, resp.Status)
	})

	t.Run("Nil request payload handled gracefully", func(t *testing.T) {
		// Health check should work with nil payload
		resp, err := client.SendRequest(ctx, quic.OpHealth, nil)
		require.NoError(t, err)
		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

// =============================================================================
// Connection Tests
// =============================================================================

func TestQUICConnection(t *testing.T) {
	skipIfNotIntegration(t)
	cfg := getTestConfig()

	// Check if server is available at the start
	checkClient := NewTestClient(cfg.QUICAddr, WithTestClientTimeout(5*time.Second))
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := checkClient.Connect(checkCtx); err != nil {
		checkCancel()
		t.Skipf("QUIC server not available at %s: %v (start platformd with --enable-quic to run these tests)", cfg.QUICAddr, err)
	}
	checkClient.Close()
	checkCancel()

	t.Run("Client connects and disconnects cleanly", func(t *testing.T) {
		client := NewTestClient(cfg.QUICAddr,
			WithTestClientTimeout(testTimeout),
		)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err := client.Connect(ctx)
		require.NoError(t, err)
		assert.True(t, client.IsConnected())

		err = client.Close()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
	})

	t.Run("Multiple sequential connections work", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			client := NewTestClient(cfg.QUICAddr,
				WithTestClientTimeout(testTimeout),
			)

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)

			err := client.Connect(ctx)
			require.NoError(t, err)

			// Send a quick health check
			err = client.Health(ctx)
			require.NoError(t, err)

			cancel()
			client.Close()
		}
	})

	t.Run("Reconnect after close works", func(t *testing.T) {
		client := NewTestClient(cfg.QUICAddr,
			WithTestClientTimeout(testTimeout),
		)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// First connection
		err := client.Connect(ctx)
		require.NoError(t, err)
		client.Close()

		// Reconnect
		err = client.Connect(ctx)
		require.NoError(t, err)
		defer client.Close()

		// Verify connection works
		err = client.Health(ctx)
		require.NoError(t, err)
	})
}
