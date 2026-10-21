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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllKMSErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		// key.go
		{"ErrInvalidKeyUsage", ErrInvalidKeyUsage{Usage: "bad"}, "bad"},

		// dek.go
		{"ErrDEKOperationFailed", ErrDEKOperationFailed{Verb: "get", Path: "/t/a", Err: errors.New("boom")}, "dek get /t/a failed: boom"},
		{"ErrDEKOperationFailed no path", ErrDEKOperationFailed{Verb: "list", Err: errors.New("boom")}, "dek list failed: boom"},
		{"ErrDEKSDKGap", ErrDEKSDKGap{Option: "list --cursor", Missing: "ListDEKsRequest.Cursor"}, "no ListDEKsRequest.Cursor"},
		{"ErrDEKServiceUnavailable", ErrDEKServiceUnavailable{}, "DEK service is not available"},
		{"ErrDEKClearSafetyNotConfirmed", ErrDEKClearSafetyNotConfirmed{Path: "/t/a"}, "pass --force"},
		{"ErrInvalidDEKLimit", ErrInvalidDEKLimit{Limit: -1}, "invalid --limit -1"},

		// key_algorithms.go

		// key_export.go
		{"ErrKeyExportNotImplemented", ErrKeyExportNotImplemented{}, "not yet implemented"},
		{"ErrKeyExportFailed", ErrKeyExportFailed{KeyID: "k1", Err: errors.New("fail")}, "k1"},
		{"ErrKeyNotExportable", ErrKeyNotExportable{KeyID: "k2"}, "k2"},
		{"ErrWriteExportedKeyFailed", ErrWriteExportedKeyFailed{Path: "/tmp/out", Err: errors.New("write err")}, "/tmp/out"},

		// key_import.go
		{"ErrKeyImportNotImplemented", ErrKeyImportNotImplemented{}, "not yet implemented"},
		{"ErrKeyImportFailed", ErrKeyImportFailed{Err: errors.New("import fail")}, "import fail"},
		{"ErrInvalidKeyMaterial", ErrInvalidKeyMaterial{Reason: "bad format"}, "bad format"},
		{"ErrKeyMaterialReadFailed", ErrKeyMaterialReadFailed{Path: "/tmp/key", Err: errors.New("read")}, "/tmp/key"},
		{"ErrInvalidWrappingAlgorithm", ErrInvalidWrappingAlgorithm{Algorithm: "DES"}, "DES"},
		{"ErrInvalidExportFormat", ErrInvalidExportFormat{Format: "xml"}, "xml"},

		// key_metadata.go
		{"ErrGetKeyMetadataFailed", ErrGetKeyMetadataFailed{KeyID: "k4", Err: errors.New("fail")}, "k4"},
		{"ErrUpdateKeyMetadataFailed", ErrUpdateKeyMetadataFailed{KeyID: "k5", Err: errors.New("fail")}, "k5"},
		{"ErrInvalidTagFormat", ErrInvalidTagFormat{Tag: "bad=tag=extra"}, "bad=tag=extra"},

		// key_policy.go
		{"ErrGetKeyPolicyFailed", ErrGetKeyPolicyFailed{KeyID: "k6", Err: errors.New("fail")}, "k6"},
		{"ErrSetKeyPolicyFailed", ErrSetKeyPolicyFailed{KeyID: "k7", Err: errors.New("fail")}, "k7"},
		{"ErrInvalidDuration", ErrInvalidDuration{Value: "xyz"}, "xyz"},

		// key_revoke.go
		{"ErrKeyRevokeFailed", ErrKeyRevokeFailed{KeyID: "k8", Err: errors.New("fail")}, "k8"},
		{"ErrRevocationReasonRequired", ErrRevocationReasonRequired{}, "reason"},

		// key_status.go
		{"ErrUpdateKeyStatusFailed", ErrUpdateKeyStatusFailed{KeyID: "k9", Err: errors.New("fail")}, "k9"},
		{"ErrInvalidKeyStatus", ErrInvalidKeyStatus{Status: "bad"}, "bad"},

		// key_test_backend.go
		{"ErrBackendTestNotImplemented", ErrBackendTestNotImplemented{}, "not yet implemented"},
		{"ErrBackendTestFailed", ErrBackendTestFailed{Err: errors.New("backend fail")}, "backend"},

		// key_unwrap.go
		{"ErrKeyUnwrapNotImplemented", ErrKeyUnwrapNotImplemented{}, "not yet implemented"},
		{"ErrKeyUnwrapFailed", ErrKeyUnwrapFailed{Err: errors.New("unwrap fail")}, "unwrap"},
		{"ErrWrappedMaterialRequired", ErrWrappedMaterialRequired{}, "wrapped"},
		{"ErrReadWrappedMaterialFailed", ErrReadWrappedMaterialFailed{Path: "/tmp/wrap", Err: errors.New("read")}, "/tmp/wrap"},

		// key_versions.go
		{"ErrListKeyVersionsFailed", ErrListKeyVersionsFailed{KeyID: "k11", Err: errors.New("fail")}, "k11"},

		// secrets.go
		{"ErrSecretNameRequired", ErrSecretNameRequired{}, "name"},
		{"ErrSecretValueRequired", ErrSecretValueRequired{}, "value"},
		{"ErrInvalidSecretValue", ErrInvalidSecretValue{Err: errors.New("bad b64")}, "bad b64"},
		{"ErrInvalidSecretVersion", ErrInvalidSecretVersion{Value: "x9"}, "x9"},
		{"ErrSecretOperationFailed", ErrSecretOperationFailed{Operation: "get", Name: "s1", Err: errors.New("fail")}, "s1"},
		{"ErrSecretsSDKGap", ErrSecretsSDKGap{Verb: "watch", Method: "SecretsClient.Watch"}, "SecretsClient.Watch"},

		// status.go
		{"ErrKMSClientNotInitialized", ErrKMSClientNotInitialized{}, "client"},
		{"ErrKMSStatusFailed", ErrKMSStatusFailed{Err: errors.New("status fail")}, "status fail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			assert.NotEmpty(t, msg)
			assert.Contains(t, msg, tt.contains)
		})
	}
}
