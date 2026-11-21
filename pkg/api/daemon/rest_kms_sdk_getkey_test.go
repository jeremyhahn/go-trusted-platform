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

package daemon

import (
	"context"
	"testing"
	"time"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// getKeyKMS answers GetKey with one fixed key; every other method is the
// embedded nil Client's.
type getKeyKMS struct {
	kmsclient.Client
	created, rotated time.Time
}

func (f getKeyKMS) GetKey(_ context.Context, keyID string) (*kmsclient.KeyInfo, error) {
	return &kmsclient.KeyInfo{
		KeyID:     keyID,
		Name:      "one",
		Algorithm: kmsclient.AlgorithmECDSAP256,
		Version:   3,
		Usage:     []kmsclient.KeyUsage{kmsclient.KeyUsageSign},
		CreatedAt: f.created,
		RotatedAt: f.rotated,
	}, nil
}

// The SDK's GetKey through the daemon route table: the mounted KMS router
// answers GET /api/v1/kms/keys/{id} with a flat key record, and the SDK REST
// transport fills GetKeyResponse's key and metadata from it (#646).
func TestSDKGetKey_ThroughTheMountedKMSRouter(t *testing.T) {
	fake := getKeyKMS{
		created: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		rotated: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
	}
	// The KMS router binds the caller's tenant: the token names one.
	s, _ := daemonRouteTableWithKMS(t, restapi.NewScopeGuard(tenantTokenValidator{}, nil, nil), fake)
	a := connectPhase35REST(t, s.Router())
	a.SetToken("tenant-a")

	resp, err := platformv1.NewKeyManagementServiceClient(a.Connection()).GetKey(context.Background(),
		&platformv1.GetKeyRequest{KeyId: "k1"})
	require.NoError(t, err)

	key := resp.GetKey()
	require.NotNil(t, key, "GetKey returns the key handle")
	assert.Equal(t, "k1", key.GetKeyId())
	assert.Equal(t, uint64(3), key.GetVersion())
	assert.Equal(t, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256, key.GetAlgorithm())
	assert.Equal(t, fake.created.Unix(), key.GetCreatedAt())

	meta := resp.GetMetadata()
	require.NotNil(t, meta, "GetKey returns the key metadata")
	assert.Equal(t, "k1", meta.GetKeyId())
	assert.Equal(t, "one", meta.GetName())
	assert.Equal(t, []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_SIGN}, meta.GetUsage())
	assert.Equal(t, uint64(3), meta.GetVersion())
	assert.Equal(t, fake.rotated.Unix(), meta.GetUpdatedAt())
}
