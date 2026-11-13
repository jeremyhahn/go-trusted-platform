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

package idevid_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestGenerateIDevID_JavaScriptSDKBody feeds the body the JavaScript SDK's
// generateIDevID sends (sdk/javascript/src/services/idevid-service.ts): the
// decoder is protojson, so the algorithm and storage must be full enum names.
func TestGenerateIDevID_JavaScriptSDKBody(t *testing.T) {
	server := &recordingServer{reply: &platformv1.GenerateIDevIDResponse{Status: ok("idevid generated")}}

	rec, _ := serve(t, server, http.MethodPost, "/api/v1/idevid/generate",
		`{"config":{"algorithm":"DEVICE_KEY_ALGORITHM_ECDSA_P384","storage":"CERT_STORAGE_TYPE_NVRAM","handle":1}}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	generate, isGenerate := server.req.(*platformv1.GenerateIDevIDRequest)
	require.True(t, isGenerate, "the router dispatched %T, want GenerateIDevIDRequest", server.req)
	assert.Equal(t, platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384, generate.GetConfig().GetAlgorithm())
	assert.Equal(t, platformv1.CertStorageType_CERT_STORAGE_TYPE_NVRAM, generate.GetConfig().GetStorage())
	assert.Equal(t, uint32(1), generate.GetConfig().GetHandle())
}

// TestGenerateIAK_ShortAlgorithmIsLost pins why the SDK maps names: protojson
// discards the short algorithm the SDK used to send.
func TestGenerateIAK_ShortAlgorithmIsLost(t *testing.T) {
	server := &recordingServer{reply: &platformv1.GenerateIAKResponse{Status: ok("iak generated")}}

	rec, _ := serve(t, server, http.MethodPost, "/api/v1/idevid/iak/generate",
		`{"config":{"algorithm":"ECDSA_P384","overwrite":true}}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	generate, isGenerate := server.req.(*platformv1.GenerateIAKRequest)
	require.True(t, isGenerate, "the router dispatched %T, want GenerateIAKRequest", server.req)
	assert.Equal(t, platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED, generate.GetConfig().GetAlgorithm())
	assert.True(t, generate.GetConfig().GetOverwrite())
}
