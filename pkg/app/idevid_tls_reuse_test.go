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
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// pemRecordingCA records the key attributes the webservice asks the CA to
// load the TLS certificate for, and reports the certificate as present so
// the webservice takes the restart path.
type pemRecordingCA struct {
	quicbaasca.CACertificateAuthority
	requested []*xkmssdk.KeyAttributes
}

// errNoTrustedRoot is the test CA's answer to TrustedRoot: it holds no root,
// so the renewal target is skipped with a warning.
type errNoTrustedRoot struct{}

func (errNoTrustedRoot) Error() string { return "test CA has no trusted root" }

func (f *pemRecordingCA) PEM(_ context.Context, attrs *xkmssdk.KeyAttributes) ([]byte, error) {
	f.requested = append(f.requested, attrs)
	return []byte("pem"), nil
}

func (f *pemRecordingCA) TrustedRoot() (*x509.Certificate, error) {
	return nil, errNoTrustedRoot{}
}

// TestInitWebServiceKeyAttributes_IDevIDReuseCarriesIDevIDSubject pins the
// TLS reuse of the provisioned IDevID (#964): a webservice whose CN matches
// tpm.idevid.cn loads its certificate under the IDevID's own subject CN,
// both straight after provisioning and after a restart that reloads the
// IDevID from the persisted TPM state. The subject is the one the IDevID
// certificate was issued with (TCG DevID v1 r12 §8.1); the webservice never
// invents one, and an empty CN would be refused by the CA with "ca: subject
// common name required".
func TestInitWebServiceKeyAttributes_IDevIDReuseCarriesIDevIDSubject(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	storage, err := xkmssdk.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	config := simulatedIDevIDConfig()
	params := &xkmssdk.TPMParams{
		Backend:   xkmssdk.NewFileBackend(logger, storage),
		Config:    config,
		FQDN:      "device-01.example.com",
		Logger:    logger,
		Transport: transport.FromReadWriter(sim),
	}

	provisioned, err := xkmssdk.NewTPM2(params)
	if errors.Is(err, xkmssdk.ErrTPMNotInitialized) {
		require.NoError(t, provisioned.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	iakAttrs, err := provisioned.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := provisioned.EKRSA()
	require.NoError(t, err)
	_, _, err = provisioned.CreateIDevID(iakAttrs, selfSignedCertificate(t, ekPub), nil)
	require.NoError(t, err)

	// A second instance on the same TPM and key store is what platformd
	// opens on every restart after the first boot.
	restarted, err := xkmssdk.NewTPM2(params)
	require.NoError(t, err)

	tests := []struct {
		name string
		tpm  xkmssdk.TrustedPlatformModule
	}{
		{name: "after provisioning", tpm: provisioned},
		{name: "after restart", tpm: restarted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := &pemRecordingCA{}
			a := &App{
				Logger:                  logging.DefaultLogger(),
				TPM:                     tc.tpm,
				TPMConfig:               *config,
				CA:                      ca,
				WebServiceKeyAttributes: map[string]*xkmssdk.KeyAttributes{},
			}
			ws := &v1.Config{Name: "api"}
			ws.Certificate.Subject.CommonName = config.IDevID.CN

			require.NoError(t, a.initWebServiceKeyAttributes(context.Background(), ws))

			require.Len(t, ca.requested, 1)
			got := ca.requested[0]
			require.Equal(t, config.IDevID.CN, got.CN,
				"the reused IDevID must carry the subject CN it was provisioned with")
			require.Equal(t, xkmssdk.KeyTypeIDevID, got.KeyType)
			require.Same(t, got, a.WebServiceKeyAttributes["api"])
		})
	}
}
