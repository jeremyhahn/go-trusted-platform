//go:build integration

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

package vtpm

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	vtpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vtpm"
)

// printCLIJSON renders v exactly as `platformctl vtpm ... --output json` does.
func printCLIJSON(t *testing.T, v any) []byte {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out).Print(v))
	return out.Bytes()
}

// The CLI prints string enums and RFC 3339 times; the adapter must decode that
// document, not the protobuf shape (integer enums, {seconds,nanos} times).
func TestCLIAdapter_DecodesTheBundleDocumentTheCLIPrints(t *testing.T) {
	created := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	printed := printCLIJSON(t, &vtpmsvc.CreateBundleResponse{Bundle: &vtpmsvc.Bundle{
		ID:        "bundle-1",
		Mode:      vtpmsvc.BundleModePreAssigned,
		CreatedAt: &created,
		Manifest: &vtpmsvc.BundleManifest{
			Hostname:    "vm-01",
			EKAlgorithm: vtpmsvc.EKAlgorithmECC,
			CreatedAt:   &created,
		},
		TPMState: &vtpmsvc.TPMState{StateDir: "/bundles/bundle-1/tpm"},
	}})

	var resp vtpmsvc.CreateBundleResponse
	require.NoError(t, json.Unmarshal(printed, &resp), "document: %s", printed)
	bundle := bundleFromCLI(resp.Bundle)

	assert.Equal(t, "bundle-1", bundle.ID)
	assert.Equal(t, vtpm.BundleModePreAssigned, bundle.Mode)
	assert.True(t, created.Equal(bundle.CreatedAt))
	require.NotNil(t, bundle.Manifest)
	assert.Equal(t, "vm-01", bundle.Manifest.Hostname)
	assert.Equal(t, vtpm.EKAlgorithmECC, bundle.Manifest.EKAlgorithm)
	assert.Equal(t, "/bundles/bundle-1/tpm", bundle.TPMState.StateDir)
}

func TestCLIAdapter_DecodesTheTemplateDocumentTheCLIPrints(t *testing.T) {
	printed := printCLIJSON(t, &vtpmsvc.ListTemplatesResponse{Templates: []*vtpmsvc.Template{{
		ID:          "tmpl-1",
		EKAlgorithm: vtpmsvc.EKAlgorithmRSA,
	}}})

	var resp vtpmsvc.ListTemplatesResponse
	require.NoError(t, json.Unmarshal(printed, &resp), "document: %s", printed)
	require.Len(t, resp.Templates, 1)
	template := templateFromCLI(resp.Templates[0])

	assert.Equal(t, "tmpl-1", template.ID)
	assert.Equal(t, vtpm.EKAlgorithmRSA, template.EKAlgorithm)
	assert.True(t, template.CreatedAt.IsZero(), "an absent created_at is the zero time")
}

func TestBundleFromCLI_LeavesAnUnknownModeEmptyAndANilBundleNil(t *testing.T) {
	assert.Nil(t, bundleFromCLI(nil))
	assert.Nil(t, templateFromCLI(nil))
	assert.Equal(t, vtpm.BundleMode(""), bundleFromCLI(&vtpmsvc.Bundle{Mode: vtpmsvc.BundleModeUnspecified}).Mode)
}
