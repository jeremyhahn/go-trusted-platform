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
	"errors"
	"testing"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// stubActivateSeam replaces loadOrInitCAForActivate for one test.
func stubActivateSeam(t *testing.T, seam func(ctx context.Context, app *App) error) {
	t.Helper()
	orig := loadOrInitCAForActivate
	loadOrInitCAForActivate = seam
	t.Cleanup(func() { loadOrInitCAForActivate = orig })
}

// A CA brought up from an empty App and then refused by the embedded
// QuicBaaS must not stay in App.CA: heartbeat and NTS read App.CA, while
// the daemon holder that gRPC, REST, QUIC, attestation and boot read stays
// empty, so leaving it published splits the readers.
func TestActivateCA_InjectionFailureUnpublishesTheCA(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger(), CAConfig: &trustedca.CAConfig{}}
	published := &anchorCA{}
	stubActivateSeam(t, func(_ context.Context, a *App) error {
		a.publishCA(published)
		return nil
	})

	ca, err := app.ActivateCA(context.Background(), func(quicbaasca.CACertificateAuthority) error {
		return errors.New("embedded CA adapter not ready")
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded CA adapter not ready")
	assert.Nil(t, ca)
	assert.Nil(t, app.CurrentCA(), "a refused CA must not stay published in App.CA")
}

func TestActivateCA_SuccessKeepsTheCA(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger(), CAConfig: &trustedca.CAConfig{}}
	published := &anchorCA{}
	stubActivateSeam(t, func(_ context.Context, a *App) error {
		a.publishCA(published)
		return nil
	})
	var injected quicbaasca.CACertificateAuthority

	ca, err := app.ActivateCA(context.Background(), func(c quicbaasca.CACertificateAuthority) error {
		injected = c
		return nil
	})

	require.NoError(t, err)
	assert.Same(t, published, ca)
	assert.Same(t, published, injected)
	assert.Same(t, published, app.CurrentCA())
}

func TestActivateCA_FailureKeepsAnEarlierCA(t *testing.T) {
	earlier := &anchorCA{}
	app := &App{Logger: logging.DefaultLogger(), CAConfig: &trustedca.CAConfig{}, CA: earlier}
	stubActivateSeam(t, func(context.Context, *App) error { return nil })

	_, err := app.ActivateCA(context.Background(), func(quicbaasca.CACertificateAuthority) error {
		return errors.New("embedded CA adapter not ready")
	})

	require.Error(t, err)
	assert.Same(t, earlier, app.CurrentCA(), "a refusal keeps the CA published before it")
}

func TestActivateCA_LoadErrorPublishesNothing(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger(), CAConfig: &trustedca.CAConfig{}}
	stubActivateSeam(t, func(context.Context, *App) error { return errors.New("load failed") })
	called := false

	_, err := app.ActivateCA(context.Background(), func(quicbaasca.CACertificateAuthority) error {
		called = true
		return nil
	})

	require.ErrorContains(t, err, "load failed")
	assert.False(t, called, "no injection without a CA")
	assert.Nil(t, app.CurrentCA())
}

// SetCA stores the CA for the embedded ceremony adapter before UpdateCA, so
// a refused injection has already handed the ceremony the CA. ActivateCA
// puts the ceremony CA from before the call back with App.CA.
func TestActivateCA_InjectionFailureRestoresTheEmbeddedCeremonyCA(t *testing.T) {
	factory, err := quicbaas.NewFactory(quicbaas.TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	es := factory.EmbeddedServer()
	require.NotNil(t, es)
	app := &App{Logger: logging.DefaultLogger(), CAConfig: &trustedca.CAConfig{}, daoFactory: factory}
	published := &anchorCA{}
	stubActivateSeam(t, func(_ context.Context, a *App) error {
		a.publishCA(published)
		return nil
	})

	_, err = app.ActivateCA(context.Background(), func(ca quicbaasca.CACertificateAuthority) error {
		es.RestoreActiveCA(ca) // what SetCA's store does before UpdateCA fails
		return errors.New("embedded CA adapter not ready")
	})

	require.Error(t, err)
	assert.Nil(t, es.ActiveCA(), "the ceremony must not keep a CA the platform refused")
	assert.Nil(t, app.CurrentCA())
}
