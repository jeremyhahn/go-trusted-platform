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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestEncodeCreateBundleRequest_FullOptions(t *testing.T) {
	body, err := EncodeCreateBundleRequest(&platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:              platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Hostname:          "node-1",
			EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
			SecureBootEnabled: true,
			Labels:            map[string]string{"env": "prod"},
			TemplateId:        "tmpl-1",
			DeviceProfileId:   7,
		},
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"mode":                "pre-assigned",
		"hostname":            "node-1",
		"ek_algorithm":        "ECC",
		"secure_boot_enabled": true,
		"labels":              map[string]string{"env": "prod"},
		"template_id":         "tmpl-1",
		"device_profile_id":   uint64(7),
	}, body)
}

func TestEncodeCreateBundleRequest_UnspecifiedValuesOmitted(t *testing.T) {
	body, err := EncodeCreateBundleRequest(&platformv1.CreateBundleRequest{})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"secure_boot_enabled": false}, body,
		"the daemon picks its own mode and EK algorithm when the SDK leaves them unspecified")
}

func TestEncodeCreateBundleRequest_UnknownEnumRejected(t *testing.T) {
	tests := []struct {
		name    string
		options *platformv1.CreateBundleOptions
		kind    string
	}{
		{"mode", &platformv1.CreateBundleOptions{Mode: platformv1.BundleMode(99)}, "bundle mode"},
		{"ek algorithm", &platformv1.CreateBundleOptions{EkAlgorithm: platformv1.EKAlgorithm(99)}, "EK algorithm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeCreateBundleRequest(&platformv1.CreateBundleRequest{Options: tt.options})

			var unknown *ErrUnknownWireValue
			require.ErrorAs(t, err, &unknown)
			assert.Equal(t, tt.kind, unknown.Kind)
		})
	}
}

func TestDecodeCreateBundleJSON_FullBundle(t *testing.T) {
	created := time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)
	data := []byte(`{
		"id": "b1",
		"mode": "template",
		"created_at": "2026-10-14T08:00:00Z",
		"cloned_from": "tmpl-1",
		"tpm_state": {"state_dir": "/s", "permall_file": "/s/permall", "volatile_file": "/s/volatile"},
		"ovmf_state": {"nvram_file": "/s/nvram"},
		"secure_boot_keys": {"dir": "/k", "pk_key": "pk.key", "pk_crt": "pk.crt"},
		"manifest": {
			"version": "1",
			"id": "b1",
			"mode": "template",
			"hostname": "node-1",
			"ek_algorithm": "RSA",
			"ek_handle": 2164260865,
			"secure_boot_enabled": true,
			"ek_certificate": {"subject": "CN=ek", "not_after": "2027-10-14T08:00:00Z"},
			"secure_boot_keys": {"pk_fingerprint": "aa", "owner_guid": "g"},
			"labels": {"env": "prod"},
			"device_profile_id": 42
		}
	}`)

	resp, err := DecodeCreateBundleJSON(data)

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	bundle := resp.GetBundle()
	assert.Equal(t, "b1", bundle.GetId())
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, bundle.GetMode())
	assert.Equal(t, created, bundle.GetCreatedAt().AsTime())
	assert.Equal(t, "tmpl-1", bundle.GetClonedFrom())
	assert.Equal(t, "/s/permall", bundle.GetTpmState().GetPermallFile())
	assert.Equal(t, "/s/nvram", bundle.GetOvmfState().GetNvramFile())
	assert.Equal(t, "pk.crt", bundle.GetSecureBootKeys().GetPkCrt())

	manifest := bundle.GetManifest()
	assert.Equal(t, "node-1", manifest.GetHostname())
	assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_RSA, manifest.GetEkAlgorithm())
	assert.Equal(t, uint32(0x81000001), manifest.GetEkHandle())
	assert.True(t, manifest.GetSecureBootEnabled())
	assert.Equal(t, "CN=ek", manifest.GetEkCertificate().GetSubject())
	assert.Equal(t, created.AddDate(1, 0, 0), manifest.GetEkCertificate().GetNotAfter().AsTime())
	assert.Nil(t, manifest.GetEkCertificate().GetNotBefore(), "an absent time stays unset")
	assert.Equal(t, "g", manifest.GetSecureBootKeys().GetOwnerGuid())
	assert.Equal(t, map[string]string{"env": "prod"}, manifest.GetLabels())
	assert.Equal(t, uint64(42), manifest.GetDeviceProfileId())
}

func TestDecodeCreateBundleJSON_InvalidReplies(t *testing.T) {
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := DecodeCreateBundleJSON([]byte(`{"id":`))

		var decodeErr *ErrWireDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, "create bundle", decodeErr.Message)
		assert.NotNil(t, errors.Unwrap(err))
	})
	t.Run("unknown bundle mode", func(t *testing.T) {
		_, err := DecodeCreateBundleJSON([]byte(`{"id":"b1","mode":"cloned"}`))

		var unknown *ErrUnknownWireValue
		require.ErrorAs(t, err, &unknown)
		assert.Equal(t, "cloned", unknown.Value)
	})
	t.Run("unknown EK algorithm", func(t *testing.T) {
		_, err := DecodeCreateBundleJSON([]byte(`{"id":"b1","manifest":{"ek_algorithm":"DSA"}}`))

		var unknown *ErrUnknownWireValue
		require.ErrorAs(t, err, &unknown)
		assert.Equal(t, "DSA", unknown.Value)
	})
}

func TestDecodeListBundlesJSON(t *testing.T) {
	resp, err := DecodeListBundlesJSON([]byte(
		`{"bundles":[{"id":"b1","mode":"template"},{"id":"b2","mode":"pre-assigned"}],"total":2}`))

	require.NoError(t, err)
	assert.Equal(t, int32(2), resp.GetTotal())
	require.Len(t, resp.GetBundles(), 2)
	assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED, resp.GetBundles()[1].GetMode())
	assert.Nil(t, resp.GetBundles()[0].GetManifest(), "a bundle without a manifest decodes without one")
}

func TestDecodeListBundlesJSON_InvalidReplies(t *testing.T) {
	_, err := DecodeListBundlesJSON([]byte(`{"bundles":"b1"}`))
	var decodeErr *ErrWireDecode
	require.ErrorAs(t, err, &decodeErr)

	_, err = DecodeListBundlesJSON([]byte(`{"bundles":[{"id":"b1","mode":"bogus"}]}`))
	var unknown *ErrUnknownWireValue
	require.ErrorAs(t, err, &unknown)
}

func TestDecodeDeleteBundleJSON(t *testing.T) {
	resp, err := DecodeDeleteBundleJSON([]byte(`{"success":true,"message":"bundle deleted"}`))

	require.NoError(t, err)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "bundle deleted", resp.GetStatus().GetMessage())

	_, err = DecodeDeleteBundleJSON([]byte(`[`))
	var decodeErr *ErrWireDecode
	require.ErrorAs(t, err, &decodeErr)
}
