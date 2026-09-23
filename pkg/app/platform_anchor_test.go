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

package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// anchorPKI is a CA with an IDevID and a service certificate it issued: the
// control plane's CA, a node's IDevID, and a platform service the node dials.
type anchorPKI struct {
	root    *x509.Certificate
	idevid  *x509.Certificate
	service *x509.Certificate
}

func newAnchorPKI(t *testing.T, cn string) *anchorPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root-ca." + cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	root := signAnchorCert(t, rootTemplate, rootTemplate, key)
	leaf := func(serial int64, name string) *x509.Certificate {
		return signAnchorCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}, root, key)
	}
	return &anchorPKI{root: root, idevid: leaf(2, "idevid."+cn), service: leaf(3, "svc."+cn)}
}

func signAnchorCert(t *testing.T, template, parent *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	pub := &key.PublicKey
	if template != parent {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub = &leafKey.PublicKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// anchorTPM serves the node's IDevID certificate, or an error when the node
// has not enrolled.
type anchorTPM struct {
	xkmssdk.TrustedPlatformModule
	idevid *x509.Certificate
	err    error
}

func (f *anchorTPM) IDevIDCertificate() (*x509.Certificate, error) { return f.idevid, f.err }

// anchorCA resolves the root of a certificate's chain from the roots it
// holds, as CA.RootCertificate does from the node's certificate store.
type anchorCA struct {
	quicbaasca.CACertificateAuthority
	roots []*x509.Certificate
}

func (f *anchorCA) RootCertificate(child *x509.Certificate) (*x509.Certificate, error) {
	for _, root := range f.roots {
		if child.CheckSignatureFrom(root) == nil {
			return root, nil
		}
	}
	return nil, errors.New("issuer " + child.Issuer.CommonName + " not found")
}

// TestPlatformAnchor_EnrolledNodeTrustsTheControlPlane is the #653 case: an
// enrolled node's own CA is not the control plane's, and the anchor must be
// the control plane CA that issued its IDevID — so a control-plane service
// verifies and a certificate from the node's local CA does not.
func TestPlatformAnchor_EnrolledNodeTrustsTheControlPlane(t *testing.T) {
	controlPlane := newAnchorPKI(t, "cp.test")
	local := newAnchorPKI(t, "compute.test")
	app := &App{
		TPM: &anchorTPM{idevid: controlPlane.idevid},
		CA:  &anchorCA{roots: []*x509.Certificate{local.root, controlPlane.root}},
	}

	anchor, err := app.PlatformAnchor()
	require.NoError(t, err)
	pool, err := anchor.CAPool(t.Context())
	require.NoError(t, err)

	_, err = controlPlane.service.Verify(x509.VerifyOptions{Roots: pool})
	assert.NoError(t, err, "a control-plane service must verify against the anchor")
	_, err = local.service.Verify(x509.VerifyOptions{Roots: pool})
	assert.Error(t, err, "the node's own local CA is not the platform CA")
}

// TestPlatformAnchor_FollowsEnrollment pins the per-call read: a node that
// enrolls after start-up is anchored from then on, without a restart, and is
// refused rather than trusted before.
func TestPlatformAnchor_FollowsEnrollment(t *testing.T) {
	controlPlane := newAnchorPKI(t, "cp.test")
	notEnrolled := errors.New("no IDevID certificate")
	tpm := &anchorTPM{err: notEnrolled}
	app := &App{TPM: tpm, CA: &anchorCA{roots: []*x509.Certificate{controlPlane.root}}}

	anchor, err := app.PlatformAnchor()
	require.NoError(t, err)

	_, err = anchor.CAPool(t.Context())
	var unavailable *trust.ErrAnchorUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.ErrorIs(t, err, notEnrolled)

	tpm.idevid, tpm.err = controlPlane.idevid, nil
	certs, err := anchor.Certificates(t.Context())
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.True(t, certs[0].Equal(controlPlane.root))
}

func TestPlatformAnchor_Unavailable(t *testing.T) {
	controlPlane := newAnchorPKI(t, "cp.test")

	t.Run("no TPM or CA", func(t *testing.T) {
		anchor, err := (&App{}).PlatformAnchor()
		require.NoError(t, err)
		_, err = anchor.TLSConfig(t.Context())
		assert.ErrorIs(t, err, ErrPlatformAnchorNoIdentity{})
	})

	t.Run("issuing chain never imported", func(t *testing.T) {
		app := &App{TPM: &anchorTPM{idevid: controlPlane.idevid}, CA: &anchorCA{}}
		anchor, err := app.PlatformAnchor()
		require.NoError(t, err)
		_, err = anchor.CAPool(t.Context())
		var unavailable *trust.ErrAnchorUnavailable
		assert.ErrorAs(t, err, &unavailable)
	})
}
