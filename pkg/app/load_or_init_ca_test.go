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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// A CA that is already loaded is kept: serve and the embedded host may both
// reach LoadOrInitCA for the same App.
func TestLoadOrInitCA_KeepsTheLoadedCA(t *testing.T) {
	loaded := &anchorCA{}
	app := &App{Logger: logging.DefaultLogger(), CA: loaded}

	require.NoError(t, app.LoadOrInitCA(context.Background(), nil))
	assert.Same(t, loaded, app.CA)
}

func TestLoadOrInitCA_RefusesANodeWithoutCAConfig(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}

	err := app.LoadOrInitCA(context.Background(), nil)
	assert.ErrorIs(t, err, ErrCANotConfigured{})
	assert.Nil(t, app.CA)
}

// A CA that can be neither loaded nor initialized reports both causes and
// leaves app.CA unset.
func TestLoadOrInitCA_ReportsBothCauses(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger(), DebugFlag: true, CAConfig: &trustedca.CAConfig{}}

	err := app.LoadOrInitCA(context.Background(), &AppInitParams{
		SOPin: []byte("so-pin"),
		Pin:   []byte("user-pin"),
	})
	var failed ErrCALoadOrInit
	require.True(t, errors.As(err, &failed), "err = %v, want ErrCALoadOrInit", err)
	assert.ErrorIs(t, err, trustedca.CAErrInvalidConfig)
	assert.Error(t, failed.InitErr)
	assert.Contains(t, err.Error(), "load error")
	assert.Contains(t, err.Error(), "init error")
	assert.Nil(t, app.CA)
}
