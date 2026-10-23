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

package quotebindtest

import (
	"bytes"
	"context"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/quotebind"
)

var (
	nonce   = []byte("quotebindtest-nonce")
	binding = bytes.Repeat([]byte{0x5a}, 32)
)

func TestBind_HandsTheBindingToTheCall(t *testing.T) {
	var capture quotebind.Capture
	if err := Bind(context.Background(), []grpc.CallOption{capture.Option()}, binding); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !bytes.Equal(capture.Binding(), binding) {
		t.Fatal("the call did not receive the binding")
	}
}

func TestBind_RefusesAnUnboundCall(t *testing.T) {
	err := Bind(context.Background(), []grpc.CallOption{grpc.WaitForReady(true)}, binding)
	var unbound *ErrUnboundCall
	if !errors.As(err, &unbound) {
		t.Fatalf("err = %v, want ErrUnboundCall", err)
	}
}

func TestQuote_CarriesTheBoundNonce(t *testing.T) {
	quoted, err := quotebind.QuotedData(Quote(nonce, binding))
	if err != nil {
		t.Fatalf("QuotedData: %v", err)
	}
	if !bytes.Equal(quoted, xkms.PeerQualifyingData(nonce, binding)) {
		t.Fatal("the quote does not carry SHA-256(nonce || binding)")
	}
	other := bytes.Repeat([]byte{0x01}, 32)
	if bytes.Equal(quoted, xkms.PeerQualifyingData(nonce, other)) {
		t.Fatal("the quote carries the nonce bound to another connection")
	}
}
