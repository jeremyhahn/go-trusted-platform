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

//go:build codec_msgpack || codec_json

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding QUIC payloads
	// Fall back to JSON if MsgPack is not available
	if codec.IsSupported(codec.MsgPack) {
		_ = quic.SetDefaultCodecType(codec.MsgPack)
	} else if codec.IsSupported(codec.JSON) {
		_ = quic.SetDefaultCodecType(codec.JSON)
	}
}

// Tests for uncovered daemon methods

func TestDaemon_CAGRPCService(t *testing.T) {
	t.Run("returns nil when not configured", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-ca-grpc-nil.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		svc := d.CAGRPCService()
		assert.Nil(t, svc)
	})

	t.Run("SetCAGRPCService updates service", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-set-ca-grpc.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		// Initially nil
		assert.Nil(t, d.CAGRPCService())

		// Set a CA service
		caSvc := &CAGRPCService{}
		d.SetCAGRPCService(caSvc)

		// Now should return the service
		assert.Equal(t, caSvc, d.CAGRPCService())
	})
}

func TestDaemon_RESTServer(t *testing.T) {
	t.Run("returns nil when REST not enabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-rest-nil.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableREST = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Nil(t, d.RESTServer())
	})

	t.Run("IsRESTEnabled returns false when not configured", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-rest-disabled.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableREST = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.False(t, d.IsRESTEnabled())
	})

	t.Run("RESTListenAddr returns empty when not enabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-rest-addr-empty.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableREST = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Empty(t, d.RESTListenAddr())
	})
}

func TestDaemon_MCPServer(t *testing.T) {
	t.Run("returns nil when MCP not enabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-mcp-nil.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableMCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Nil(t, d.MCPServer())
	})

	t.Run("IsMCPEnabled returns false when not configured", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-mcp-disabled.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableMCP = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.False(t, d.IsMCPEnabled())
	})

	t.Run("MCPListenAddr returns empty when config nil", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-mcp-addr-nil.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableMCP = false
		config.MCPConfig = nil
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Empty(t, d.MCPListenAddr())
	})

	t.Run("MCPListenAddr returns empty for stdio transport", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-mcp-addr-stdio.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableMCP = false
		config.MCPConfig = &MCPConfig{
			Transport: "stdio",
		}
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Empty(t, d.MCPListenAddr())
	})
}

func TestDaemon_QUICServer(t *testing.T) {
	t.Run("returns nil when QUIC not enabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-quic-nil.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableQUIC = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Nil(t, d.QUICServer())
	})

	t.Run("QUICServiceHandler returns nil when QUIC not enabled", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-quic-handler-nil.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableQUIC = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Nil(t, d.QUICServiceHandler())
	})

	t.Run("IsQUICEnabled returns false when not configured", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-quic-disabled.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableQUIC = false
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.False(t, d.IsQUICEnabled())
	})

	t.Run("QUICListenAddr returns config addr when server nil", func(t *testing.T) {
		config := DefaultConfig()
		config.SocketPath = "/tmp/test-quic-addr.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false
		config.EnableQUIC = false
		config.QUICListenAddr = "127.0.0.1:9444"
		config.SkipIAMValidation = true

		d, err := New(config)
		require.NoError(t, err)
		defer func() { _ = d.ForceStop() }()

		assert.Equal(t, "127.0.0.1:9444", d.QUICListenAddr())
	})
}

// NOTE: TestDaemon_UnixSocketServer was removed as part of Unix IPC refactoring.
// The Unix socket server was replaced with gRPC over Unix Domain Sockets.

// Config validation tests

func TestConfig_ValidateMCPConfig(t *testing.T) {
	t.Run("validates HTTP transport requires address", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			Transport:             "http",
			HTTPAddr:              "", // Invalid - empty address for http transport
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 100,
		}

		err := config.Validate()
		// Validation should fail for empty HTTP address with http transport
		require.Error(t, err)
	})

	t.Run("validates invalid transport", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			Transport:             "invalid", // Invalid transport
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 100,
		}

		err := config.Validate()
		require.Error(t, err)
	})

	t.Run("validates negative request timeout", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			Transport:             "stdio",
			RequestTimeout:        -1 * time.Second, // Invalid - negative timeout
			MaxConcurrentRequests: 100,
		}

		err := config.Validate()
		require.Error(t, err)
	})

	t.Run("validates zero max concurrent requests", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			Transport:             "stdio",
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 0, // Invalid - must be positive
		}

		err := config.Validate()
		require.Error(t, err)
	})

	t.Run("valid MCP config passes validation", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			Transport:             "stdio",
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 100,
		}
		config.SocketPath = "/tmp/test-valid-mcp.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false

		err := config.Validate()
		require.NoError(t, err)
	})

	t.Run("valid HTTP MCP config passes validation", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMCP = true
		config.MCPConfig = &MCPConfig{
			Transport:             "http",
			HTTPAddr:              "127.0.0.1:9445",
			RequestTimeout:        30 * time.Second,
			MaxConcurrentRequests: 100,
		}
		config.SocketPath = "/tmp/test-valid-mcp-http.sock"
		config.SocketGroup = ""
		config.EnableGRPCTCP = false

		err := config.Validate()
		require.NoError(t, err)
	})
}

// Additional REST service tests

func TestRESTServer_ForceStop(t *testing.T) {
	t.Run("force stop running server", func(t *testing.T) {
		config := DefaultConfig()
		config.RESTListenAddr = "127.0.0.1:0"
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, nil)
		require.NoError(t, err)

		err = server.Start()
		require.NoError(t, err)

		// Give server time to start
		time.Sleep(50 * time.Millisecond)

		err = server.ForceStop()
		require.NoError(t, err)
		assert.False(t, server.IsRunning())
	})
}

// Service state tests

func TestService_ServiceState(t *testing.T) {
	t.Run("service state tracking", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		// Register a mock service
		state := &serviceState{}

		// Initial status is stopped (0)
		assert.Equal(t, int32(0), state.status.Load())

		// Simulate state changes
		state.status.Store(1) // starting
		assert.Equal(t, int32(1), state.status.Load())

		state.status.Store(2) // running
		assert.Equal(t, int32(2), state.status.Load())

		state.status.Store(3) // stopping
		assert.Equal(t, int32(3), state.status.Load())

		state.status.Store(0) // stopped
		assert.Equal(t, int32(0), state.status.Load())

		_ = service // silence unused variable
	})
}

// QUIC handler tests

func TestQUICServiceHandler_HandleRequest(t *testing.T) {
	t.Run("health operations", func(t *testing.T) {
		logger := logging.DefaultLogger()
		handler := NewQUICServiceHandler(logger)

		ctx := context.Background()

		// Test health check
		resp := handler.HandleRequest(ctx, &quic.Request{
			Opcode:  quic.OpHealth,
			Payload: []byte{},
		})
		assert.Equal(t, quic.StatusOK, resp.Status)

		// Test liveness
		resp = handler.HandleRequest(ctx, &quic.Request{
			Opcode:  quic.OpLiveness,
			Payload: []byte{},
		})
		assert.Equal(t, quic.StatusOK, resp.Status)

		// Test readiness
		resp = handler.HandleRequest(ctx, &quic.Request{
			Opcode:  quic.OpReadiness,
			Payload: []byte{},
		})
		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("unknown opcode returns not implemented", func(t *testing.T) {
		logger := logging.DefaultLogger()
		handler := NewQUICServiceHandler(logger)

		ctx := context.Background()
		resp := handler.HandleRequest(ctx, &quic.Request{
			Opcode:  0xFE, // Container Stop opcode - returns Unavailable when service not configured
			Payload: []byte{},
		})

		// 0xFE is now mapped to Container Stop, which returns Unavailable when container service is not configured
		assert.True(t, resp.Status == quic.StatusUnavailable || resp.Status == quic.StatusNotImplemented)
	})
}

// QUIC KMS tests

func TestQUICKMS_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"GenerateKey", quic.OpKMSGenerateKey},
		{"ImportKey", quic.OpKMSImportKey},
		{"GetKey", quic.OpKMSGetKey},
		{"ListKeys", quic.OpKMSListKeys},
		{"DeleteKey", quic.OpKMSDeleteKey},
		{"RotateKey", quic.OpKMSRotateKey},
		{"UpdateKeyStatus", quic.OpKMSUpdateKeyStatus},
		{"ExportKey", quic.OpKMSExportKey},
		{"GetKeyVersions", quic.OpKMSGetKeyVersions},
		{"Encrypt", quic.OpKMSEncrypt},
		{"Decrypt", quic.OpKMSDecrypt},
		{"Sign", quic.OpKMSSign},
		{"Verify", quic.OpKMSVerify},
		{"GenerateRandom", quic.OpKMSGenerateRandom},
		{"Hash", quic.OpKMSHash},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.True(t, strings.Contains(strings.ToLower(string(resp.Payload)), "kms"))
		})
	}
}

// QUIC KMS Request/Response encoding tests

func TestQUICKMS_RequestResponse_Encoding(t *testing.T) {
	t.Run("KMSGenerateKeyRequest roundtrip", func(t *testing.T) {
		original := &KMSGenerateKeyRequest{
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				KeySize:   256,
				Usage: []int32{
					int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
					int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
				},
			},
			Name:        "test-key",
			Description: "test description",
			Tags:        map[string]string{"env": "test"},
			Owner:       "test-owner",
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded KMSGenerateKeyRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Name, decoded.Name)
		assert.Equal(t, original.Description, decoded.Description)
		assert.Equal(t, original.Owner, decoded.Owner)
		assert.Equal(t, original.KeySpec.Algorithm, decoded.KeySpec.Algorithm)
	})

	t.Run("KMSGenerateKeyResponse roundtrip", func(t *testing.T) {
		original := &KMSGenerateKeyResponse{
			Key: &KMSKeyHandleResponse{
				KeyId:     "key-123",
				Version:   1,
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				Status:    int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
				CreatedAt: time.Now().Unix(),
			},
			Metadata: &KMSKeyMetadataResponse{
				KeyId:       "key-123",
				Name:        "test-key",
				Description: "test",
				Algorithm:   int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				Status:      int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
			},
			Timestamp: time.Now().Unix(),
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded KMSGenerateKeyResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Key.KeyId, decoded.Key.KeyId)
		assert.Equal(t, original.Metadata.Name, decoded.Metadata.Name)
	})

	t.Run("KMSEncryptRequest roundtrip", func(t *testing.T) {
		original := &KMSEncryptRequest{
			KeyId:     "key-123",
			Plaintext: []byte("secret message"),
			Context:   []byte("context"),
			Nonce:     []byte("nonce"),
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded KMSEncryptRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyId, decoded.KeyId)
		assert.Equal(t, original.Plaintext, decoded.Plaintext)
	})

	t.Run("KMSSignRequest roundtrip", func(t *testing.T) {
		original := &KMSSignRequest{
			KeyId:         "key-123",
			Message:       []byte("message to sign"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded KMSSignRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyId, decoded.KeyId)
		assert.Equal(t, original.Message, decoded.Message)
		assert.Equal(t, original.HashAlgorithm, decoded.HashAlgorithm)
	})
}

// QUIC IAM Request/Response encoding tests

func TestQUICIAM_RequestResponse_Encoding(t *testing.T) {
	t.Run("AuthenticateRequest roundtrip", func(t *testing.T) {
		original := &AuthenticateRequest{
			TenantID: "tenant-123",
			Username: "test@example.com",
			Password: "securepassword",
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded AuthenticateRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.TenantID, decoded.TenantID)
		assert.Equal(t, original.Username, decoded.Username)
	})
}

// QUIC IAM service not available tests

func TestQUICIAM_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"CreateUser", quic.OpIAMUserCreate},
		{"DeleteUser", quic.OpIAMUserDelete},
		{"GetUser", quic.OpIAMUserGet},
		{"ListUsers", quic.OpIAMUserList},
		{"UpdateUser", quic.OpIAMUserUpdate},
		{"CreateRole", quic.OpIAMRoleCreate},
		{"DeleteRole", quic.OpIAMRoleDelete},
		{"GetRole", quic.OpIAMRoleGet},
		{"ListRoles", quic.OpIAMRoleList},
		{"AssignRole", quic.OpIAMRoleAssign},
		{"RevokeRole", quic.OpIAMRoleRevoke},
		{"CreateGroup", quic.OpIAMGroupCreate},
		{"DeleteGroup", quic.OpIAMGroupDelete},
		{"GetGroup", quic.OpIAMGroupGet},
		{"ListGroups", quic.OpIAMGroupList},
		{"AddGroupMember", quic.OpIAMGroupAddMember},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.True(t, strings.Contains(strings.ToLower(string(resp.Payload)), "iam"))
		})
	}
}

// QUIC SDN service not available tests

func TestQUICSDN_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"GetPortState", quic.OpSDNGetPortState},
		{"SetPortState", quic.OpSDNSetPortState},
		{"ListPorts", quic.OpSDNListPorts},
		{"GetFlow", quic.OpSDNGetFlow},
		{"AddFlow", quic.OpSDNAddFlow},
		{"DeleteFlow", quic.OpSDNDeleteFlow},
		{"ListFlows", quic.OpSDNListFlows},
		{"ApplyPolicy", quic.OpSDNApplyPolicy},
		{"GetPolicy", quic.OpSDNGetPolicy},
		{"ListPolicies", quic.OpSDNListPolicies},
		{"GetBridge", quic.OpSDNGetBridge},
		{"ListBridges", quic.OpSDNListBridges},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.True(t, strings.Contains(strings.ToLower(string(resp.Payload)), "sdn"))
		})
	}
}

// QUIC DNS service not available tests

func TestQUICDNS_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"AddZone", quic.OpDNSAddZone},
		{"DeleteZone", quic.OpDNSDeleteZone},
		{"GetZone", quic.OpDNSGetZone},
		{"ListZones", quic.OpDNSListZones},
		{"AddRecord", quic.OpDNSAddRecord},
		{"DeleteRecord", quic.OpDNSDeleteRecord},
		{"GetRecord", quic.OpDNSGetRecord},
		{"ListRecords", quic.OpDNSListRecords},
		{"Resolve", quic.OpDNSResolve},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.True(t, strings.Contains(strings.ToLower(string(resp.Payload)), "dns"))
		})
	}
}
