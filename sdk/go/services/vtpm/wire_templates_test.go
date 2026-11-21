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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestEncodeCreateTemplateRequest_EachEKAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		alg  platformv1.EKAlgorithm
		wire any
	}{
		{"rsa", platformv1.EKAlgorithm_EK_ALGORITHM_RSA, "RSA"},
		{"ecc", platformv1.EKAlgorithm_EK_ALGORITHM_ECC, "ECC"},
		{"unspecified", platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := EncodeCreateTemplateRequest(&platformv1.CreateTemplateRequest{
				Options: &platformv1.CreateTemplateOptions{
					Id:                "tpl-1",
					Description:       "golden",
					EkAlgorithm:       tt.alg,
					SecureBootEnabled: true,
				},
			})
			require.NoError(t, err)
			assert.Equal(t, "tpl-1", body["id"])
			assert.Equal(t, "golden", body["description"])
			assert.Equal(t, true, body["secure_boot_enabled"])
			alg, present := body["ek_algorithm"]
			if tt.wire == nil {
				assert.False(t, present, "UNSPECIFIED is left out")
				return
			}
			assert.Equal(t, tt.wire, alg)
		})
	}
}

func TestEncodeCreateTemplateRequest_Refusals(t *testing.T) {
	_, err := EncodeCreateTemplateRequest(&platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{Id: "tpl-1", EkAlgorithm: platformv1.EKAlgorithm(99)},
	})
	var unknown *ErrUnknownWireValue
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "EK algorithm", unknown.Kind)

	_, err = EncodeCreateTemplateRequest(&platformv1.CreateTemplateRequest{})
	var missing *errRequiredWireField
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "options.id", missing.Field)
}

func TestEncodeCloneTemplateRequest(t *testing.T) {
	body, err := EncodeCloneTemplateRequest(&platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{Hostname: "node-a", Labels: map[string]string{"role": "edge"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "node-a", body["hostname"])
	assert.Equal(t, map[string]string{"role": "edge"}, body["labels"])
	assert.NotContains(t, body, "template_id")

	_, err = EncodeCloneTemplateRequest(&platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{}})
	var missing *errRequiredWireField
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "options.hostname", missing.Field)
}

func TestDecodeTemplateJSON_EachEKAlgorithm(t *testing.T) {
	created := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		wire string
		alg  platformv1.EKAlgorithm
	}{
		{"RSA", platformv1.EKAlgorithm_EK_ALGORITHM_RSA},
		{"ECC", platformv1.EKAlgorithm_EK_ALGORITHM_ECC},
	}
	for _, tt := range tests {
		t.Run(tt.wire, func(t *testing.T) {
			raw := `{"id":"tpl-1","description":"golden","tpm_state_dir":"/t/tpm","nvram_path":"/t/nvram",` +
				`"secure_boot_keys_dir":"/t/sb","ek_algorithm":"` + tt.wire + `","secure_boot_enabled":true,` +
				`"created_at":"2026-11-16T12:00:00Z"}`
			resp, err := DecodeTemplateJSON([]byte(raw))
			require.NoError(t, err)
			tpl := resp.GetTemplate()
			assert.Equal(t, "tpl-1", tpl.GetId())
			assert.Equal(t, "golden", tpl.GetDescription())
			assert.Equal(t, "/t/tpm", tpl.GetTpmStateDir())
			assert.Equal(t, "/t/nvram", tpl.GetNvramPath())
			assert.Equal(t, "/t/sb", tpl.GetSecureBootKeysDir())
			assert.Equal(t, tt.alg, tpl.GetEkAlgorithm())
			assert.True(t, tpl.GetSecureBootEnabled())
			assert.True(t, created.Equal(tpl.GetCreatedAt().AsTime()))

			createResp, err := DecodeCreateTemplateJSON([]byte(raw))
			require.NoError(t, err)
			assert.True(t, createResp.GetStatus().GetSuccess())
			assert.Equal(t, tt.alg, createResp.GetTemplate().GetEkAlgorithm())
		})
	}
}

func TestDecodeTemplateJSON_ZeroCreatedAt(t *testing.T) {
	resp, err := DecodeTemplateJSON([]byte(`{"id":"tpl-1","ek_algorithm":"RSA"}`))
	require.NoError(t, err)
	assert.Nil(t, resp.GetTemplate().GetCreatedAt())
}

func TestDecodeTemplateJSON_UnknownEKAlgorithm(t *testing.T) {
	_, err := DecodeTemplateJSON([]byte(`{"id":"tpl-1","ek_algorithm":"DSA"}`))
	var unknown *ErrUnknownWireValue
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "DSA", unknown.Value)

	_, err = DecodeListTemplatesJSON([]byte(`{"templates":[{"id":"a","ek_algorithm":"DSA"}]}`))
	require.ErrorAs(t, err, &unknown)
}

func TestDecodeTemplateJSON_InvalidReply(t *testing.T) {
	_, err := DecodeTemplateJSON([]byte(`[`))
	var decode *ErrWireDecode
	require.ErrorAs(t, err, &decode)
}

func TestDecodeListTemplatesJSON(t *testing.T) {
	resp, err := DecodeListTemplatesJSON([]byte(`{"templates":[{"id":"a","ek_algorithm":"RSA"},{"id":"b","ek_algorithm":"ECC"}]}`))
	require.NoError(t, err)
	require.Len(t, resp.GetTemplates(), 2)
	assert.Equal(t, "a", resp.GetTemplates()[0].GetId())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, resp.GetTemplates()[1].GetEkAlgorithm())
}

func TestDecodeDeleteTemplateJSON(t *testing.T) {
	resp, err := DecodeDeleteTemplateJSON([]byte(`{"success":true,"message":"template deleted"}`))
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "template deleted", resp.GetStatus().GetMessage())
}

func TestDecodeCloneTemplateJSON(t *testing.T) {
	resp, err := DecodeCloneTemplateJSON([]byte(`{"id":"bundle-1","mode":"template","cloned_from":"tpl-1",` +
		`"manifest":{"id":"bundle-1","hostname":"node-a","ek_algorithm":"ECC"}}`))
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "bundle-1", resp.GetBundle().GetId())
	assert.Equal(t, "tpl-1", resp.GetBundle().GetClonedFrom())
	assert.Equal(t, "node-a", resp.GetBundle().GetManifest().GetHostname())
}

// The daemon (pkg/api/rest) replies to a clone with a flat bundle: hostname,
// labels, ek_algorithm, secure_boot_enabled and the EK certificate sit at the
// top level, not inside a manifest. The decoder builds the Manifest from them.
func TestDecodeCloneTemplateJSON_DaemonFlatShape(t *testing.T) {
	resp, err := DecodeCloneTemplateJSON([]byte(`{"id":"bundle-1","mode":"pre-assigned",` +
		`"hostname":"node-a","ek_algorithm":"ECC","secure_boot_enabled":true,"running":false,` +
		`"created_at":"2026-11-17T10:00:00Z","cloned_from":"tpl-1","labels":{"env":"prod"},` +
		`"ek_certificate":{"subject":"CN=node-a","issuer":"CN=ca","serial_number":"42",` +
		`"not_before":"2026-11-17T10:00:00Z","not_after":"2027-11-17T10:00:00Z","fingerprint":"ab:cd"},` +
		`"secure_boot_keys":{"pk_fingerprint":"pk","kek_fingerprint":"kek","db_fingerprint":"db"}}`))
	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())

	bundle := resp.GetBundle()
	assert.Equal(t, "bundle-1", bundle.GetId())
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, bundle.GetMode())
	assert.Equal(t, "tpl-1", bundle.GetClonedFrom())
	assert.Nil(t, bundle.GetSecureBootKeys(), "the flat fingerprints are not key paths")

	manifest := bundle.GetManifest()
	require.NotNil(t, manifest)
	assert.Equal(t, "bundle-1", manifest.GetId())
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, manifest.GetMode())
	assert.Equal(t, "node-a", manifest.GetHostname())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, manifest.GetEkAlgorithm())
	assert.True(t, manifest.GetSecureBootEnabled())
	assert.Equal(t, map[string]string{"env": "prod"}, manifest.GetLabels())
	assert.Equal(t, "tpl-1", manifest.GetClonedFrom())
	assert.Equal(t, "CN=node-a", manifest.GetEkCertificate().GetSubject())
	assert.Equal(t, "ab:cd", manifest.GetEkCertificate().GetFingerprint())
	assert.Equal(t, "pk", manifest.GetSecureBootKeys().GetPkFingerprint())
	assert.Equal(t, "db", manifest.GetSecureBootKeys().GetDbFingerprint())
}
