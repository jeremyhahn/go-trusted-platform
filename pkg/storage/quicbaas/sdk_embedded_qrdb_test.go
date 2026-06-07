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
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildEmbeddedQRDBServicers_NilServerReturnsTypedError verifies the
// helper surfaces a typed EmbeddedQRDBWiringError when the caller passes
// a nil embedded server (the "not constructed yet" case).
func TestBuildEmbeddedQRDBServicers_NilServerReturnsTypedError(t *testing.T) {
	servicers, err := buildEmbeddedQRDBServicers(nil)
	require.Error(t, err)
	assert.Nil(t, servicers.KV)
	assert.Nil(t, servicers.Admin)

	var wiringErr *EmbeddedQRDBWiringError
	require.True(t, stderrors.As(err, &wiringErr), "want EmbeddedQRDBWiringError, got %T", err)
	assert.Equal(t, "embedded server", wiringErr.Stage)
}

// TestBuildEmbeddedQRDBServicers_ServerNotStartedReturnsTypedError verifies
// the helper distinguishes "no server" from "server not started" so the
// caller can produce actionable diagnostics.
func TestBuildEmbeddedQRDBServicers_ServerNotStartedReturnsTypedError(t *testing.T) {
	// An EmbeddedServer constructed but not started has nil .server.
	es := &EmbeddedServer{}
	servicers, err := buildEmbeddedQRDBServicers(es)
	require.Error(t, err)
	assert.Nil(t, servicers.KV)

	var wiringErr *EmbeddedQRDBWiringError
	require.True(t, stderrors.As(err, &wiringErr), "want EmbeddedQRDBWiringError, got %T", err)
	assert.Equal(t, "embedded server not started", wiringErr.Stage)
}

// TestEmbeddedQRDBOption_NilServerReturnsTypedError verifies the option
// builder rejects a nil server with the same typed wiring error so option
// composition fails fast at SDK construction time.
func TestEmbeddedQRDBOption_NilServerReturnsTypedError(t *testing.T) {
	opt, err := embeddedQRDBOption(nil)
	require.Error(t, err)
	assert.Nil(t, opt)

	var wiringErr *EmbeddedQRDBWiringError
	require.True(t, stderrors.As(err, &wiringErr), "want EmbeddedQRDBWiringError, got %T", err)
}

// TestEmbeddedQRDBOption_NotStartedServerReturnsTypedError verifies the
// option builder also rejects an unstarted server before reaching the qrdb
// SDK so callers see a localized wiring error instead of a deeper SDK
// transport diagnostic.
func TestEmbeddedQRDBOption_NotStartedServerReturnsTypedError(t *testing.T) {
	opt, err := embeddedQRDBOption(&EmbeddedServer{})
	require.Error(t, err)
	assert.Nil(t, opt)

	var wiringErr *EmbeddedQRDBWiringError
	require.True(t, stderrors.As(err, &wiringErr), "want EmbeddedQRDBWiringError, got %T", err)
}

// TestEmbeddedQRDBWiringError_ErrorIncludesStage verifies the error string
// names the failing stage so log scrapers can route the diagnostic.
func TestEmbeddedQRDBWiringError_ErrorIncludesStage(t *testing.T) {
	e := &EmbeddedQRDBWiringError{Stage: "shard transport"}
	assert.Contains(t, e.Error(), "shard transport")
	assert.Contains(t, e.Error(), "unavailable")
}

// TestEmbeddedQRDBWiringError_ErrorIncludesCause verifies the error string
// surfaces the underlying cause when one is set.
func TestEmbeddedQRDBWiringError_ErrorIncludesCause(t *testing.T) {
	cause := stderrors.New("boom")
	e := &EmbeddedQRDBWiringError{Stage: "sharded client", Cause: cause}
	got := e.Error()
	assert.Contains(t, got, "sharded client")
	assert.Contains(t, got, "boom")
	assert.ErrorIs(t, e, cause)
}

// TestNewSDKClientWithEmbeddedServer_NilServerForEmbeddedFails verifies the
// new constructor rejects embedded mode without an embedded server (the
// caller cannot wire qrdb in-process without one).
func TestNewSDKClientWithEmbeddedServer_NilServerForEmbeddedFails(t *testing.T) {
	cfg := TestConfig(t)
	require.Equal(t, TransportEmbedded, cfg.Transport)

	client, err := NewSDKClientWithEmbeddedServer(cfg, nil)
	require.Error(t, err)
	assert.Nil(t, client)

	var embeddedErr ErrEmbeddedServiceRequired
	assert.ErrorAs(t, err, &embeddedErr)
}

// TestNewSDKClientWithEmbeddedServer_InvalidConfigReturnsTypedError verifies
// the constructor validates configuration before touching the embedded
// server.
func TestNewSDKClientWithEmbeddedServer_InvalidConfigReturnsTypedError(t *testing.T) {
	cfg := &Config{
		Transport: TransportEmbedded,
		// DataDir missing — Validate() will fail.
	}
	client, err := NewSDKClientWithEmbeddedServer(cfg, nil)
	require.Error(t, err)
	assert.Nil(t, client)
}
