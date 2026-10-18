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

package vtpm

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// cliCreateBundleOutput is what `platformctl vtpm create --output json`
// printed in CI run 56173 (the paths are shortened, the rest is verbatim).
const cliCreateBundleOutput = `{
  "status": { "success": true },
  "bundle": {
    "id": "CLI-1792277777-create-preassigned-1792277777941032200",
    "mode": "BUNDLE_MODE_PRE_ASSIGNED",
    "created_at": "2026-10-17T22:56:18.299147635Z",
    "manifest": {
      "hostname": "CLI-1792277777-create-preassigned",
      "ek_algorithm": "RSA",
      "secure_boot_enabled": false,
      "created_at": "2026-10-17T22:56:18.299147635Z",
      "checksums": { "ovmf/OVMF_VARS.fd": "sha256:5d2a", "tpm/tpm2-00.permall": "sha256:8fcf" },
      "ek_certificate": { "fingerprint": "sha256:3a8d" }
    },
    "tpm_state": { "state_dir": "/vtpm/b/tpm", "permall_file": "/vtpm/b/tpm/tpm2-00.permall" },
    "ovmf_state": { "nvram_file": "/vtpm/b/ovmf/OVMF_VARS.fd" }
  }
}
`

func TestDecodeCLIResponse_CreateBundleOutput(t *testing.T) {
	resp, err := decodeCLIResponse[vtpmsvc.CreateBundleResponse]("CreateBundle", []byte(cliCreateBundleOutput))
	require.NoError(t, err)

	bundle := bundleFromDomain(resp.Bundle)
	require.NotNil(t, bundle)

	createdAt, err := time.Parse(time.RFC3339Nano, "2026-10-17T22:56:18.299147635Z")
	require.NoError(t, err)

	assert.Equal(t, "CLI-1792277777-create-preassigned-1792277777941032200", bundle.ID)
	assert.Equal(t, vtpm.BundleModePreAssigned, bundle.Mode)
	assert.True(t, createdAt.Equal(bundle.CreatedAt))
	require.NotNil(t, bundle.Manifest)
	assert.Equal(t, vtpm.EKAlgorithmRSA, bundle.Manifest.EKAlgorithm)
	require.NotNil(t, bundle.Manifest.EKCertificate)
	assert.Equal(t, "sha256:3a8d", bundle.Manifest.EKCertificate.Fingerprint)
	require.NotNil(t, bundle.TPMState)
	assert.Equal(t, "/vtpm/b/tpm", bundle.TPMState.StateDir)
	require.NotNil(t, bundle.OVMFState)
	assert.Equal(t, "/vtpm/b/ovmf/OVMF_VARS.fd", bundle.OVMFState.NVRAMFile)
}

func TestDecodeCLIResponse_MalformedOutputWrapsDecodeError(t *testing.T) {
	_, err := decodeCLIResponse[vtpmsvc.CreateBundleResponse]("CreateBundle", []byte(`{"bundle": {"mode": 2`))
	require.Error(t, err)

	var adapterErr *CLIAdapterError
	require.ErrorAs(t, err, &adapterErr)
	assert.Equal(t, "CreateBundle", adapterErr.Operation)

	var syntaxErr *json.SyntaxError
	assert.True(t, errors.As(err, &syntaxErr), "the json decode error must be wrapped, got %v", err)
}
