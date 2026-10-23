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

package quic

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnectionTLS_RoundTrip(t *testing.T) {
	state := &tls.ConnectionState{ServerName: "control-plane.example"}

	got := ConnectionTLS(WithConnectionTLS(context.Background(), state))

	assert.Same(t, state, got)
}

func TestConnectionTLS_AbsentWithoutAQUICConnection(t *testing.T) {
	assert.Nil(t, ConnectionTLS(context.Background()))
	assert.Nil(t, ConnectionTLS(context.WithValue(context.Background(), connectionTLSKey{}, "not a state")))
}
