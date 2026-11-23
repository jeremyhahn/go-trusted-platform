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
	"encoding/pem"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
)

// liveCA is a signing test CA that also answers RootCertificate, which the
// heartbeat pool and the platform anchor call.
type liveCA struct{ *signingNTSCA }

func (c liveCA) RootCertificate(*x509.Certificate) (*x509.Certificate, error) { return c.root, nil }

// TestApp_LiveCAReaders_RaceThePublish pins that every App.CA reader that runs
// while the daemon serves (BMC enrolment's issuer lookup, the NTS served-cert
// check and reissue, the heartbeat CA pool, the platform anchor) reads the CA
// through CurrentCA: InitCA publishes it at runtime, and go test -race reports
// any direct read of app.CA racing that publish.
func TestApp_LiveCAReaders_RaceThePublish(t *testing.T) {
	root, key := mintTestCA(t, "platform-root")
	leaf := mintLeaf(t, root, key, "cp-test.example.test")
	ca := liveCA{&signingNTSCA{root: root, key: key}}

	app := ntsTestApp()
	app.NTPConfig.Mode = ntp.ModeBoth
	app.ntpApplier = &recordingNTPApplier{}
	anchorApp := &App{Logger: logging.DefaultLogger(), TPM: &anchorTPM{idevid: leaf}}

	var wg sync.WaitGroup
	start := make(chan struct{})
	reader := func(read func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				read()
			}
		}()
	}
	reader(func() { _, _ = app.ntsServedCertInvalid(leaf) })
	reader(func() { _, _ = app.heartbeatServerPool(leaf) })
	reader(func() { _ = app.bmcIssuerCAPEM() })
	reader(func() { _, _ = anchorApp.platformAnchorCertificates(context.Background()) })
	// One goroutine only: SignCSR records lastCSR on the test CA.
	reader(func() {
		_ = app.reissueNTSCertificate(context.Background(), newFakeSecretStore(),
			"platform/ntp/nts-key", "platform/ntp/nts-cert")
	})

	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		app.publishCA(ca)
	}()
	go func() {
		defer wg.Done()
		<-start
		anchorApp.publishCA(ca)
	}()
	close(start)
	wg.Wait()

	block, _ := pem.Decode(app.bmcIssuerCAPEM())
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, root.Raw, block.Bytes)

	reason, invalid := app.ntsServedCertInvalid(leaf)
	assert.False(t, invalid, reason)
}

// TestApp_BMCIssuerCAPEM_NilWithoutCA pins that BMC enrolment gets no issuer
// PEM before a CA is published.
func TestApp_BMCIssuerCAPEM_NilWithoutCA(t *testing.T) {
	assert.Nil(t, (&App{Logger: logging.DefaultLogger()}).bmcIssuerCAPEM())
}
