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

package kms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// errCLIKMSMock is the sentinel error returned by unstubbed fake methods.
var errCLIKMSMock = errors.New("cli kms mock: method not stubbed")

// fakeKMSClient implements quicbaassdk.KMSClient with hookable functions
// for the verbs exercised by the CLI lifecycle commands.
type fakeKMSClient struct {
	revokeKeyFn              func(ctx context.Context, keyID string) error
	getKeyMetadataFn         func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error)
	updateKeyMetadataFn      func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error)
	setKeyPolicyFn           func(ctx context.Context, req *kms.SetKeyPolicyRequest) error
	getKeyPolicyFn           func(ctx context.Context, keyID string) (*kms.KeyPolicy, error)
	getSupportedAlgorithmsFn func(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error)
	backendStatusFn          func(ctx context.Context) (*kms.BackendStatusResponse, error)
}

var _ quicbaassdk.KMSClient = (*fakeKMSClient)(nil)

func (f *fakeKMSClient) GenerateKey(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) GetPublicKey(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) ListKeys(ctx context.Context) (*kms.ListKeysResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) RotateKey(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) DeleteKey(ctx context.Context, keyID string) error {
	return errCLIKMSMock
}

func (f *fakeKMSClient) ImportKey(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) ExportKey(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) RevokeKey(ctx context.Context, keyID, _ string) error {
	if f.revokeKeyFn != nil {
		return f.revokeKeyFn(ctx, keyID)
	}
	return errCLIKMSMock
}

func (f *fakeKMSClient) ListKeyVersions(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	if f.getKeyMetadataFn != nil {
		return f.getKeyMetadataFn(ctx, keyID)
	}
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) UpdateKeyMetadata(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
	if f.updateKeyMetadataFn != nil {
		return f.updateKeyMetadataFn(ctx, req)
	}
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) SetKeyPolicy(ctx context.Context, req *kms.SetKeyPolicyRequest) error {
	if f.setKeyPolicyFn != nil {
		return f.setKeyPolicyFn(ctx, req)
	}
	return errCLIKMSMock
}

func (f *fakeKMSClient) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	if f.getKeyPolicyFn != nil {
		return f.getKeyPolicyFn(ctx, keyID)
	}
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) SetKeyRotationPolicy(ctx context.Context, req *kms.SetKeyRotationPolicyRequest) (*kms.KeyRotationPolicy, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) GetKeyRotationPolicy(ctx context.Context, keyID string) (*kms.KeyRotationPolicy, error) {
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) DeleteKeyRotationPolicy(ctx context.Context, keyID string) error {
	return errCLIKMSMock
}

func (f *fakeKMSClient) GetSupportedAlgorithms(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
	if f.getSupportedAlgorithmsFn != nil {
		return f.getSupportedAlgorithmsFn(ctx)
	}
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) BackendStatus(ctx context.Context) (*kms.BackendStatusResponse, error) {
	if f.backendStatusFn != nil {
		return f.backendStatusFn(ctx)
	}
	return nil, errCLIKMSMock
}

func (f *fakeKMSClient) UnwrapKey(ctx context.Context, req *kms.UnwrapKeyRequest) (*kms.UnwrapKeyResponse, error) {
	return nil, errCLIKMSMock
}

// newTestKMSPrinter builds a JSON printer that discards output.
func newTestKMSPrinter() *cli.Printer {
	return cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, discardWriter{})
}

// discardWriter drops all output.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// =============================================================================
// Factory
// =============================================================================

func TestSetKMSClientFactory(t *testing.T) {
	t.Run("OverrideAndRestore", func(t *testing.T) {
		fake := &fakeKMSClient{}
		restore := SetKMSClientFactory(func(base *cli.BaseCommand) (quicbaassdk.KMSClient, error) {
			return fake, nil
		})

		client, err := openKMSClient(nil)
		require.NoError(t, err)
		assert.Same(t, fake, client)

		restore()
		assert.NotNil(t, activeKMSClientFactory)
	})

	t.Run("FactoryError", func(t *testing.T) {
		factoryErr := errors.New("no daemon")
		restore := SetKMSClientFactory(func(base *cli.BaseCommand) (quicbaassdk.KMSClient, error) {
			return nil, factoryErr
		})
		defer restore()

		_, err := openKMSClient(nil)
		assert.ErrorIs(t, err, factoryErr)
	})
}

// =============================================================================
// Parse helpers
// =============================================================================

func TestParseSDKKeyUsages(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		usages, err := parseSDKKeyUsages([]string{"encrypt", "decrypt", "sign", "verify", "wrap", "unwrap"})
		require.NoError(t, err)
		assert.Equal(t, []kms.KeyUsage{
			kms.KeyUsageEncrypt,
			kms.KeyUsageDecrypt,
			kms.KeyUsageSign,
			kms.KeyUsageVerify,
			kms.KeyUsageWrap,
			kms.KeyUsageUnwrap,
		}, usages)
	})

	t.Run("WrapKeyAlias", func(t *testing.T) {
		usage, err := parseSDKKeyUsage("wrap-key")
		require.NoError(t, err)
		assert.Equal(t, kms.KeyUsageWrap, usage)
	})

	t.Run("Invalid", func(t *testing.T) {
		_, err := parseSDKKeyUsages([]string{"encrypt", "launch-missiles"})
		var invalidErr ErrInvalidKeyUsage
		assert.ErrorAs(t, err, &invalidErr)
	})
}

func TestParseTagPairs(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		tags, err := parseTagPairs([]string{"env=prod", "team=security", "note=a=b"})
		require.NoError(t, err)
		assert.Equal(t, "prod", tags["env"])
		assert.Equal(t, "security", tags["team"])
		assert.Equal(t, "a=b", tags["note"])
	})

	t.Run("Empty", func(t *testing.T) {
		tags, err := parseTagPairs(nil)
		require.NoError(t, err)
		assert.Nil(t, tags)
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		_, err := parseTagPairs([]string{"no-equals-sign"})
		var invalidErr ErrInvalidTagFormat
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("EmptyKey", func(t *testing.T) {
		_, err := parseTagPairs([]string{"=value"})
		var invalidErr ErrInvalidTagFormat
		assert.ErrorAs(t, err, &invalidErr)
	})
}

// =============================================================================
// Revoke
// =============================================================================

func TestExecuteKeyRevoke(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		revoked := ""
		client := &fakeKMSClient{
			revokeKeyFn: func(ctx context.Context, keyID string) error {
				revoked = keyID
				return nil
			},
		}
		err := executeKeyRevoke(ctx, client, newTestKMSPrinter(), "key-1", "compromised")
		require.NoError(t, err)
		assert.Equal(t, "key-1", revoked)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKeyRevoke(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", "compromised")
		var revokeErr ErrKeyRevokeFailed
		require.ErrorAs(t, err, &revokeErr)
		assert.Equal(t, "key-1", revokeErr.KeyID)
	})
}

func TestRunKeyRevokeRequiresReason(t *testing.T) {
	err := runKeyRevoke(&cli.CommonFlags{}, "key-1", "")
	var reasonErr ErrRevocationReasonRequired
	assert.ErrorAs(t, err, &reasonErr)
}

// =============================================================================
// Metadata
// =============================================================================

func TestExecuteKeyMetadataGet(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		client := &fakeKMSClient{
			getKeyMetadataFn: func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
				return &kms.KeyMetadataResponse{
					KeyID:     keyID,
					Name:      "prod-key",
					Algorithm: kms.AlgorithmAES256GCM,
					Status:    kms.KeyStatusEnabled,
					Usage:     []kms.KeyUsage{kms.KeyUsageEncrypt},
					Version:   2,
				}, nil
			},
		}
		err := executeKeyMetadataGet(ctx, client, newTestKMSPrinter(), "key-1")
		require.NoError(t, err)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKeyMetadataGet(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "missing")
		var getErr ErrGetKeyMetadataFailed
		require.ErrorAs(t, err, &getErr)
		assert.Equal(t, "missing", getErr.KeyID)
	})
}

func TestExecuteKeyMetadataUpdate(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		var captured *kms.UpdateKeyMetadataRequest
		client := &fakeKMSClient{
			updateKeyMetadataFn: func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
				captured = req
				return &kms.KeyMetadataResponse{KeyID: req.KeyID, Name: req.Name}, nil
			},
		}
		err := executeKeyMetadataUpdate(ctx, client, newTestKMSPrinter(), "key-1", "renamed", "new desc",
			[]string{"env=prod"}, []string{"old"})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, "renamed", captured.Name)
		assert.Equal(t, "new desc", captured.Description)
		assert.Equal(t, "prod", captured.Tags["env"])
		assert.Equal(t, []string{"old"}, captured.RemoveTags)
	})

	t.Run("InvalidTag", func(t *testing.T) {
		err := executeKeyMetadataUpdate(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", "", "",
			[]string{"badtag"}, nil)
		var invalidErr ErrInvalidTagFormat
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKeyMetadataUpdate(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", "name", "", nil, nil)
		var updateErr ErrUpdateKeyMetadataFailed
		assert.ErrorAs(t, err, &updateErr)
	})
}

// =============================================================================
// Policy
// =============================================================================

func TestExecuteKeyPolicyGet(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		client := &fakeKMSClient{
			getKeyPolicyFn: func(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
				return &kms.KeyPolicy{
					KeyID:             keyID,
					Version:           1,
					AllowedOperations: []kms.KeyUsage{kms.KeyUsageSign},
					AllowedPrincipals: []string{"user:alice"},
				}, nil
			},
		}
		err := executeKeyPolicyGet(ctx, client, newTestKMSPrinter(), "key-1")
		require.NoError(t, err)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKeyPolicyGet(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1")
		var getErr ErrGetKeyPolicyFailed
		assert.ErrorAs(t, err, &getErr)
	})
}

func TestExecuteKeyPolicySet(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		var captured *kms.SetKeyPolicyRequest
		client := &fakeKMSClient{
			setKeyPolicyFn: func(ctx context.Context, req *kms.SetKeyPolicyRequest) error {
				captured = req
				return nil
			},
		}
		err := executeKeyPolicySet(ctx, client, newTestKMSPrinter(), "key-1", keyPolicySetOptions{
			Operations:       []string{"sign", "verify"},
			AllowPrincipals:  []string{"user:alice"},
			DenyPrincipals:   []string{"user:mallory"},
			ExpiresIn:        "7d",
			RotationRequired: true,
			MaxUsageCount:    100,
			RequireMFA:       true,
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		require.NotNil(t, captured.Policy)
		assert.Equal(t, "key-1", captured.Policy.KeyID)
		assert.Equal(t, []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify}, captured.Policy.AllowedOperations)
		assert.Equal(t, []string{"user:alice"}, captured.Policy.AllowedPrincipals)
		assert.Equal(t, []string{"user:mallory"}, captured.Policy.DeniedPrincipals)
		assert.True(t, captured.Policy.RotationRequired)
		assert.Equal(t, uint64(100), captured.Policy.MaxUsageCount)
		assert.True(t, captured.Policy.RequireMFA)
		assert.False(t, captured.Policy.ExpiresAt.IsZero())
	})

	t.Run("InvalidOperation", func(t *testing.T) {
		err := executeKeyPolicySet(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", keyPolicySetOptions{
			Operations: []string{"launch-missiles"},
		})
		var invalidErr ErrInvalidKeyUsage
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("InvalidDuration", func(t *testing.T) {
		err := executeKeyPolicySet(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", keyPolicySetOptions{
			ExpiresIn: "not-a-duration",
		})
		var durationErr ErrInvalidDuration
		assert.ErrorAs(t, err, &durationErr)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKeyPolicySet(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", keyPolicySetOptions{})
		var setErr ErrSetKeyPolicyFailed
		assert.ErrorAs(t, err, &setErr)
	})
}

// =============================================================================
// Algorithms
// =============================================================================

func TestExecuteKeyAlgorithms(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		client := &fakeKMSClient{
			getSupportedAlgorithmsFn: func(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
				return &kms.SupportedAlgorithmsResponse{Algorithms: []string{"AES-256-GCM", "ED25519"}}, nil
			},
		}
		err := executeKeyAlgorithms(ctx, client, newTestKMSPrinter())
		require.NoError(t, err)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKeyAlgorithms(ctx, &fakeKMSClient{}, newTestKMSPrinter())
		var algErr ErrAlgorithmsFailed
		assert.ErrorAs(t, err, &algErr)
	})
}

// =============================================================================
// Backend status
// =============================================================================

func TestExecuteKMSStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessJSON", func(t *testing.T) {
		client := &fakeKMSClient{
			backendStatusFn: func(ctx context.Context) (*kms.BackendStatusResponse, error) {
				return &kms.BackendStatusResponse{
					BackendType:  "tpm2",
					Status:       "healthy",
					Device:       "/dev/tpmrm0",
					PCRBanks:     []string{"SHA256"},
					PCRRegisters: []int{0, 7},
					Capabilities: map[string]bool{"seal": true},
				}, nil
			},
		}
		err := executeKMSStatus(ctx, client, newTestKMSPrinter(), cli.OutputFormatJSON)
		require.NoError(t, err)
	})

	t.Run("SuccessTable", func(t *testing.T) {
		client := &fakeKMSClient{
			backendStatusFn: func(ctx context.Context) (*kms.BackendStatusResponse, error) {
				return &kms.BackendStatusResponse{BackendType: "software", Status: "healthy"}, nil
			},
		}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, discardWriter{})
		err := executeKMSStatus(ctx, client, printer, cli.OutputFormatTable)
		require.NoError(t, err)
	})

	t.Run("BackendError", func(t *testing.T) {
		err := executeKMSStatus(ctx, &fakeKMSClient{}, newTestKMSPrinter(), cli.OutputFormatJSON)
		var statusErr ErrKMSStatusFailed
		assert.ErrorAs(t, err, &statusErr)
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		client := &fakeKMSClient{
			backendStatusFn: func(ctx context.Context) (*kms.BackendStatusResponse, error) {
				return &kms.BackendStatusResponse{}, nil
			},
		}
		err := executeKMSStatus(ctx, client, newTestKMSPrinter(), cli.OutputFormat("bogus"))
		var formatErr cli.ErrInvalidOutputFormat
		assert.ErrorAs(t, err, &formatErr)
	})
}
