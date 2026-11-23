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

package quicbaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// RestoreActiveCA puts back the ceremony CA SetCA stored before a failed
// UpdateCA, without touching the server's CertificateService.
func TestEmbeddedServer_RestoreActiveCA(t *testing.T) {
	factory, err := NewFactory(TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	es := factory.EmbeddedServer()
	require.NotNil(t, es)
	assert.Nil(t, es.ActiveCA())

	ca := &stubTrustedCA{}
	es.RestoreActiveCA(ca)
	assert.Same(t, ca, es.ActiveCA())

	es.RestoreActiveCA(nil)
	assert.Nil(t, es.ActiveCA())
}

func TestFactory_ActiveCA_EmbeddedPassesThrough(t *testing.T) {
	factory, err := NewFactory(TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	assert.Nil(t, factory.ActiveCA())

	ca := &stubTrustedCA{}
	factory.RestoreCA(ca)
	assert.Same(t, ca, factory.ActiveCA())
	assert.Same(t, ca, factory.EmbeddedServer().ActiveCA())

	factory.RestoreCA(nil)
	assert.Nil(t, factory.ActiveCA())
	assert.Nil(t, factory.EmbeddedServer().ActiveCA())
}

func TestFactory_ActiveCA_RemoteModeIsNilAndRestoreNoOp(t *testing.T) {
	factory, err := NewFactory(RemoteConfig(TransportGRPC, "localhost:10443"), logging.DefaultLogger(), nil)
	require.NoError(t, err)

	assert.Nil(t, factory.ActiveCA())
	factory.RestoreCA(&stubTrustedCA{})
	assert.Nil(t, factory.ActiveCA())
}

func TestFactory_ActiveCA_ClosedIsNilAndRestoreNoOp(t *testing.T) {
	factory, err := NewFactory(TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	factory.mu.Lock()
	factory.closed = true
	factory.mu.Unlock()

	factory.RestoreCA(&stubTrustedCA{})
	assert.Nil(t, factory.ActiveCA())
	assert.Nil(t, factory.EmbeddedServer().ActiveCA())
}
