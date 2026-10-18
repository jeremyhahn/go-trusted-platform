package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// kmsSecretToolCase is one KMS or secret tool driven through tools/call: the
// scope of its gRPC method, arguments its handler accepts, and a hook that
// records when the handler reaches the service.
type kmsSecretToolCase struct {
	tool  string
	scope string
	args  map[string]interface{}
	hook  func(svc *mockServiceProvider, ran *bool)
}

// kmsSecretToolCases lists every KMS and secret tool with the scope of the
// gRPC method it mirrors (pkg/api/grpc/method_permissions.go, #304).
func kmsSecretToolCases() []kmsSecretToolCase {
	const msg = "aGVsbG8=" // "hello", base64-encoded
	keyID := map[string]interface{}{"key_id": "key-1"}
	secretID := map[string]interface{}{"secret_id": "secret-1"}

	return []kmsSecretToolCase{
		{"kms_generate_key", "kms:write",
			map[string]interface{}{"name": "k", "algorithm": "AES-256-GCM", "usage": []interface{}{"ENCRYPT"}},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsCreateKeyFunc = func(context.Context, *KMSCreateKeyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_rotate_key", "kms:write", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsRotateKeyFunc = func(context.Context, string) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_revoke_key", "kms:write", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsRevokeKeyFunc = func(context.Context, string, string) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_update_key_metadata", "kms:write", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsUpdateKeyMetadataFunc = func(context.Context, *KMSUpdateKeyMetadataRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_update_key_status", "kms:write", map[string]interface{}{"key_id": "key-1", "status": "disabled"},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsUpdateKeyStatusFunc = func(context.Context, *KMSUpdateKeyStatusRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_set_key_policy", "kms:write", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsSetKeyPolicyFunc = func(context.Context, *KMSSetKeyPolicyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_get_key", "kms:read", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGetKeyFunc = func(context.Context, string, uint64) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_list_keys", "kms:read", map[string]interface{}{},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsListKeysFunc = func(context.Context, int, int) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"keys": []interface{}{}}, nil
				}
			}},
		{"kms_export_public_key", "kms:read", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsExportPublicKeyFunc = func(context.Context, *KMSExportPublicKeyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_get_key_metadata", "kms:read", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGetKeyMetadataFunc = func(context.Context, string) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_get_key_policy", "kms:read", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGetKeyPolicyFunc = func(context.Context, string) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_supported_algorithms", "kms:read", map[string]interface{}{},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGetSupportedAlgorithmsFunc = func(context.Context) ([]string, error) {
					*ran = true
					return []string{"AES-256-GCM"}, nil
				}
			}},
		{"kms_backend_status", "kms:read", map[string]interface{}{},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsBackendStatusFunc = func(context.Context) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"status": "healthy"}, nil
				}
			}},
		{"kms_delete_key", "kms:delete", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsDeleteKeyFunc = func(context.Context, string) error {
					*ran = true
					return nil
				}
			}},
		{"kms_encrypt", "kms:write", map[string]interface{}{"key_id": "key-1", "plaintext": msg},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsEncryptFunc = func(context.Context, *KMSEncryptRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"ciphertext": msg}, nil
				}
			}},
		{"kms_sign", "kms:write", map[string]interface{}{"key_id": "key-1", "message": msg},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsSignFunc = func(context.Context, *KMSSignRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"signature": msg}, nil
				}
			}},
		{"kms_generate_data_key", "kms:write", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGenerateDataKeyFunc = func(context.Context, *KMSGenerateDataKeyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_generate_wrapped_data_key", "kms:write", keyID,
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGenerateWrappedDataKeyFunc = func(context.Context, *KMSGenerateWrappedDataKeyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"key_id": "key-1"}, nil
				}
			}},
		{"kms_decrypt", "kms:read", map[string]interface{}{"key_id": "key-1", "ciphertext": msg},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsDecryptFunc = func(context.Context, *KMSDecryptRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"plaintext": msg}, nil
				}
			}},
		{"kms_verify", "kms:read", map[string]interface{}{"key_id": "key-1", "message": msg, "signature": msg},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsVerifyFunc = func(context.Context, *KMSVerifyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"valid": true}, nil
				}
			}},
		{"kms_random", "kms:read", map[string]interface{}{"num_bytes": 16},
			func(s *mockServiceProvider, ran *bool) {
				s.kmsGenerateRandomFunc = func(context.Context, int) ([]byte, error) {
					*ran = true
					return make([]byte, 16), nil
				}
			}},
		{"secret_store", "secrets:write", map[string]interface{}{"secret_id": "secret-1", "data": msg},
			func(s *mockServiceProvider, ran *bool) {
				s.secretStoreFunc = func(context.Context, *SecretStoreRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"secret_id": "secret-1"}, nil
				}
			}},
		{"secret_set_rotation_policy", "secrets:write", secretID,
			func(s *mockServiceProvider, ran *bool) {
				s.secretSetRotationPolicyFunc = func(context.Context, *SecretSetRotationPolicyRequest) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"secret_id": "secret-1"}, nil
				}
			}},
		{"secret_get", "secrets:read", secretID,
			func(s *mockServiceProvider, ran *bool) {
				s.secretGetFunc = func(context.Context, string, uint64) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"secret_id": "secret-1", "data": msg}, nil
				}
			}},
		{"secret_get_rotation_policy", "secrets:read", secretID,
			func(s *mockServiceProvider, ran *bool) {
				s.secretGetRotationPolicyFunc = func(context.Context, string) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"secret_id": "secret-1"}, nil
				}
			}},
		{"secret_list", "secrets:list", map[string]interface{}{},
			func(s *mockServiceProvider, ran *bool) {
				s.secretListFunc = func(context.Context, int, string) (interface{}, error) {
					*ran = true
					return map[string]interface{}{"secrets": []interface{}{}}, nil
				}
			}},
		{"secret_delete", "secrets:delete", secretID,
			func(s *mockServiceProvider, ran *bool) {
				s.secretDeleteFunc = func(context.Context, string) error {
					*ran = true
					return nil
				}
			}},
	}
}

// callKMSSecretTool runs one tools/call for tc with a caller whose grants
// are decided by grant, and reports the response and whether the handler
// reached the service.
func callKMSSecretTool(t *testing.T, tc kmsSecretToolCase, grant func(permission string) bool) (*mcpwire.JSONRPCResponse, bool) {
	t.Helper()

	ran := false
	svc := newMockServiceProvider()
	tc.hook(svc, &ran)

	authz := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return grant(resource + ":" + action), nil
		},
	}
	server := NewServer(svc, &Config{AuthorizationService: authz}, newTestLogger())

	args := make(map[string]interface{}, len(tc.args))
	for k, v := range tc.args {
		args[k] = v
	}
	req := &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      tc.tool,
			"arguments": args,
			"_token":    "caller-token",
		},
	}
	return server.handleRequest(context.Background(), req), ran
}

// TestKMSAndSecretToolsAuthorizeByGRPCScope proves each KMS and secret tool
// answers a caller holding its gRPC method's scope, and refuses a caller
// holding every other scope before the handler runs.
func TestKMSAndSecretToolsAuthorizeByGRPCScope(t *testing.T) {
	for _, tc := range kmsSecretToolCases() {
		t.Run(tc.tool, func(t *testing.T) {
			t.Run("with scope", func(t *testing.T) {
				resp, ran := callKMSSecretTool(t, tc, func(p string) bool { return p == tc.scope })
				require.Nil(t, resp.Error, "%s with %s", tc.tool, tc.scope)
				assert.True(t, ran, "%s handler must reach the service", tc.tool)
			})

			t.Run("without scope", func(t *testing.T) {
				resp, ran := callKMSSecretTool(t, tc, func(p string) bool { return p != tc.scope })
				require.NotNil(t, resp.Error, "%s without %s must be refused", tc.tool, tc.scope)
				assert.Equal(t, mcpwire.PermissionDenied, resp.Error.Code)
				assert.False(t, ran, "%s handler must not run when refused", tc.tool)
			})
		})
	}
}

// TestKMSAndSecretToolCasesCoverEveryRegisteredTool keeps the scope table
// above complete: a new kms_ or secret_ tool must be added to it.
func TestKMSAndSecretToolCasesCoverEveryRegisteredTool(t *testing.T) {
	covered := make(map[string]bool)
	for _, tc := range kmsSecretToolCases() {
		covered[tc.tool] = true
	}

	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	for _, def := range registry.ListTools() {
		if strings.HasPrefix(def.Name, "kms_") || strings.HasPrefix(def.Name, "secret_") {
			assert.True(t, covered[def.Name], "%s has no scope case", def.Name)
		}
	}
}
