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

package bmc

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

func TestRunConsole_NoMode(t *testing.T) {
	err := runConsole(context.Background(), &standaloneBMCFlags{}, "", false, nil, 0)
	var nomode ErrBMCNoMode
	require.ErrorAs(t, err, &nomode)
}

func TestRunConsole_RedfishProtocolRejected(t *testing.T) {
	err := runConsole(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		user:     "admin",
		password: "secret",
		protocol: string(bmc.ProtocolRedfish),
	}, "", false, nil, 0)
	var notSupported ErrBMCConsoleNotSupported
	require.ErrorAs(t, err, &notSupported)
	assert.Equal(t, string(bmc.ProtocolRedfish), notSupported.Protocol)
}

func TestRunConsole_ConsoleActivateError(t *testing.T) {
	mock := bmc.NewMockClient()
	mock.ConsoleErr = errors.New("activate boom")
	defer withMockBMCClient(t, mock)()

	err := runConsole(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		user:     "admin",
		password: "secret",
		protocol: string(bmc.ProtocolIPMI),
	}, "", false, nil, 0)
	var act ErrBMCConsoleActivate
	require.ErrorAs(t, err, &act)
	assert.Equal(t, int64(1), mock.ConsoleCalls())
}

// TestCtlXReader_PassesThroughBytesUntilEscape verifies that the disconnect
// reader returns errCtrlX exactly when it encounters the escape byte.
func TestCtlXReader_PassesThroughBytesUntilEscape(t *testing.T) {
	src := strings.NewReader("hello\x1Dworld")
	cr := &ctlXReader{r: src}

	buf := make([]byte, 16)
	n, err := cr.Read(buf)
	require.ErrorIs(t, err, errCtrlX)
	assert.Equal(t, "hello", string(buf[:n]))
}

func TestCtlXReader_NoEscapePassesThrough(t *testing.T) {
	src := strings.NewReader("hello")
	cr := &ctlXReader{r: src}

	buf := make([]byte, 16)
	n, err := cr.Read(buf)
	// io.EOF is reported by the underlying reader once the buffer drains.
	assert.True(t, err == nil || errors.Is(err, io.EOF))
	assert.Equal(t, "hello", string(buf[:n]))
}
