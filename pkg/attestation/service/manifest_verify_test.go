// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
)

func storedManifest() *manifest.HostManifest {
	return &manifest.HostManifest{ID: "m-1", HostID: "host-a", Timestamp: time.Now().UTC(), Nonce: []byte{1, 2, 3}, MerkleRoot: []byte{9}}
}

// A supplied public key cannot be checked against the manifest, so the
// service refuses rather than report the signature valid, and records no
// verification it did not perform (#304).
func TestVerifyManifest_RefusesAPublicKeyItCannotCheck(t *testing.T) {
	svc, _ := newVerdictService(t)

	result, err := svc.VerifyManifest(context.Background(), storedManifest(), nil, nil, []byte("-----BEGIN PUBLIC KEY-----"), nil)

	require.ErrorAs(t, err, new(daemon.ErrAttestationManifestSignatureUnchecked))
	assert.Nil(t, result)
	assert.Empty(t, eventKinds(t, svc, "host-a"))
}

func TestVerifyManifest_WithoutAKeyStillVerifies(t *testing.T) {
	svc, _ := newVerdictService(t)

	result, err := svc.VerifyManifest(context.Background(), storedManifest(), nil, []byte{1, 2, 3}, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, manifest.VerificationStatusVerified, result.Status)
	assert.True(t, result.NonceValid)
	assert.Equal(t, []store.EventKind{store.EventKindManifestVerified}, eventKinds(t, svc, "host-a"))
}
