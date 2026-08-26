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

package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TPM NV limits measured against the go-tpm-tools reference simulator while
// diagnosing #80. They are the ceilings the NVRAM persistence path imposes
// and this store does not.
const (
	tpmNVBufferMax = 1024 // TPM_PT_NV_BUFFER_MAX — per-command write chunk
	tpmNVIndexMax  = 2048 // TPM_PT_NV_INDEX_MAX  — total size of one NV index
)

// certOfAtLeast builds a self-signed certificate whose DER encoding is at
// least size bytes, padded with an inert extension.
func certOfAtLeast(t *testing.T, cn string, size int) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// An unknown non-critical extension is ignored by every consumer and
	// lets the encoded length be dialled to a chosen size.
	padding := make([]byte, size)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: padding,
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(der), size,
		"padding did not produce a certificate of the intended size")

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestCertStoreHasNoNVSizeCeiling is the size half of the #80 regression net.
//
// #80's interim routes IDevID certificate persistence away from TPM NVRAM and
// into this store, because go-xkms defines the NV index as a counter
// (go-xkms#138). Size is the second reason that route matters: an NV index is
// capped at TPM_PT_NV_INDEX_MAX (2048 bytes measured), so a certificate larger
// than that could never be persisted through NVRAM even once the counter bug
// is fixed. A real IDevID carrying TCG platform extensions can exceed it.
//
// This pins that the store itself imposes no such ceiling — including a
// certificate past both the per-command buffer and the whole-index limit —
// so the routing decision is sound rather than merely convenient.
func TestCertStoreHasNoNVSizeCeiling(t *testing.T) {
	logger := logging.DefaultLogger()

	for _, tc := range []struct {
		name    string
		minSize int
	}{
		{"typical leaf", 512},
		{"larger than TPM_PT_NV_BUFFER_MAX", tpmNVBufferMax + 256},
		{"larger than TPM_PT_NV_INDEX_MAX", tpmNVIndexMax + 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objStore, err := object.NewObjectStore(logger, object.NewMemoryClient(), t.TempDir(), nil)
			require.NoError(t, err)

			cs, storage, err := NewCertificateStoreWithStorage(logger, objStore)
			require.NoError(t, err)
			adapter := NewTPM2CertStoreAdapterWithStorage(logger, cs, storage)

			cert := certOfAtLeast(t, "node-07-idevid", tc.minSize)
			attrs := &xkmssdk.KeyAttributes{CN: "node-07-idevid"}

			require.NoError(t, adapter.Save(attrs, cert),
				"the certificate store must not impose the TPM NV index ceiling")

			got, err := adapter.Get(attrs)
			require.NoError(t, err)
			assert.Equal(t, cert.Raw, got.Raw,
				"the certificate must round-trip byte-identical")
		})
	}
}

// TestCertStorePersistsBothIdentityCertClasses covers the boundary that all
// four of #62's TPM certificate persistence calls converge on.
//
// The four calls — IAK and IDevID, each on the local-issuance and ACME
// paths — cannot be driven at unit level: they need a live TPM, and the
// ACME pair needs an ACME server. What they share is this store. Under the
// #74 and #80 interims every one of them resolves here, differing only in
// which certificate class they hand over and under which key. So exercising
// this boundary with both classes is the closest honest unit-level cover
// for all four, and it is deliberately paired with the routing assertion in
// pkg/app (TestTPMIdentityPersistenceIsRoutedToTheCertStore), which pins
// that they actually arrive here.
//
// The two classes are stored under different keys, so persisting one must
// never disturb the other — the failure that would surface as one identity
// silently overwriting the other's certificate.
func TestCertStorePersistsBothIdentityCertClasses(t *testing.T) {
	logger := logging.DefaultLogger()

	objStore, err := object.NewObjectStore(logger, object.NewMemoryClient(), t.TempDir(), nil)
	require.NoError(t, err)
	cs, storage, err := NewCertificateStoreWithStorage(logger, objStore)
	require.NoError(t, err)
	adapter := NewTPM2CertStoreAdapterWithStorage(logger, cs, storage)

	// The keys the interims settle on: IAK under the upstream default
	// (its CN is left empty, #74), IDevID under the hostname (#80).
	iakAttrs := &xkmssdk.KeyAttributes{CN: "default-device-id"}
	idevidAttrs := &xkmssdk.KeyAttributes{CN: "node-07-idevid"}

	iakCert := certOfAtLeast(t, "node-07-iak", tpmNVBufferMax+128)
	idevidCert := certOfAtLeast(t, "node-07-idevid", tpmNVIndexMax+128)

	require.NoError(t, adapter.Save(iakAttrs, iakCert))
	require.NoError(t, adapter.Save(idevidAttrs, idevidCert))

	gotIAK, err := adapter.Get(iakAttrs)
	require.NoError(t, err)
	assert.Equal(t, iakCert.Raw, gotIAK.Raw, "the IAK certificate must round-trip byte-identical")

	gotIDevID, err := adapter.Get(idevidAttrs)
	require.NoError(t, err)
	assert.Equal(t, idevidCert.Raw, gotIDevID.Raw, "the IDevID certificate must round-trip byte-identical")

	assert.NotEqual(t, gotIAK.Raw, gotIDevID.Raw,
		"the two identities must not collide on one storage key")
}
