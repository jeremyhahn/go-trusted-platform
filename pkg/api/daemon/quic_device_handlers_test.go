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

package daemon

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestDeviceRetiredOpcodes_AnswerUnknownOpcode pins 0x3C (Deactivate) and
// 0x3E (GetMetrics), retired unimplemented in #317. The authorization catalog
// no longer classifies them, so the wire refuses them before dispatch, and the
// device dispatcher itself answers the unknown-opcode error, never a stub.
func TestDeviceRetiredOpcodes_AnswerUnknownOpcode(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)
	for _, opcode := range []byte{0x3C, 0x3E} {
		t.Run(fmt.Sprintf("0x%02X", opcode), func(t *testing.T) {
			req := &quicwire.Request{Opcode: opcode, Payload: []byte{}}

			resp := handler.HandleRequest(context.Background(), req)
			assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
			assert.Equal(t, quic.ErrOperationNotClassified{Opcode: opcode}.Error(), string(resp.Payload))

			resp = handler.handleDeviceOperation(context.Background(), req)
			assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
			assert.Equal(t, ErrQUICUnknownOpcode{Opcode: opcode}.Error(), string(resp.Payload))
		})
	}
}

// TestDeviceOperation_AttributesNotOwnedByDeviceDispatcher pins that
// OpDeviceAttributes (0x6D) is the IDevID dispatcher's opcode: the device
// dispatcher, which the wire never routes 0x6D to, answers the unknown-opcode
// error rather than a not-implemented stub. The served path is covered by
// TestQUICDeviceAttributes_Success.
func TestDeviceOperation_AttributesNotOwnedByDeviceDispatcher(t *testing.T) {
	handler, _ := newQUICDeviceProfileHandler(t)
	req := &quicwire.Request{Opcode: quicwire.OpDeviceAttributes, Payload: []byte{}}

	resp := handler.handleDeviceOperation(context.Background(), req)

	assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
	assert.Equal(t, ErrQUICUnknownOpcode{Opcode: quicwire.OpDeviceAttributes}.Error(), string(resp.Payload))
}
