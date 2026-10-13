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

package nbd

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// TestErrors checks that each error names what an operator needs to act
// on, and that wrapped causes stay reachable with errors.Is.
func TestErrors(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	tests := []struct {
		err        error
		mentions   []string
		wrapsCause bool
	}{
		{ErrInvalidConfig{Field: "VolumeSize", Reason: "too small"}, []string{"VolumeSize", "too small"}, false},
		{ErrServeFailed{Cause: cause}, []string{"serve failed"}, true},
		{ErrUnsupportedClientFlags{Flags: 0x80}, []string{"0x80"}, false},
		{ErrTLSRequired{Option: optGo}, []string{"option 7", "TLS is required"}, false},
		{ErrTLSHandshake{Cause: cause}, []string{"handshake"}, true},
		{ErrClientCertificateRequired{}, []string{"certificate required"}, false},
		{ErrClientCertificateUntrusted{Subject: "CN=node-01", Cause: cause}, []string{"CN=node-01"}, true},
		{ErrTrustAnchor{Cause: cause}, []string{"anchor"}, true},
		{ErrUnknownIdentity{Identity: "node-01"}, []string{`"node-01"`}, false},
		{ErrExportNotPermitted{Identity: "node-01", Export: "node-02"}, []string{`"node-01"`, `"node-02"`}, false},
		{ErrVolume{Identity: "node-01", Op: "sync", Cause: cause}, []string{`"node-01"`, "sync"}, true},
		{ErrProtocol{Reason: "bad magic"}, []string{"bad magic"}, false},
		{ErrProtocol{Reason: "read header", Cause: cause}, []string{"read header"}, true},
		{ErrServerRefused{Option: optGo, Reply: repErrPolicy}, []string{"NBD_OPT_GO", "NBD_REP_ERR_POLICY"}, false},
		{ErrServerRefused{Option: 99, Reply: repFlagError | 99}, []string{"0x63", "0x80000063"}, false},
	}
	for _, tc := range tests {
		msg := tc.err.Error()
		if !strings.HasPrefix(msg, "nbd: ") {
			t.Errorf("%T: message %q lacks the package prefix", tc.err, msg)
		}
		for _, want := range tc.mentions {
			if !strings.Contains(msg, want) {
				t.Errorf("%T: message %q does not mention %q", tc.err, msg, want)
			}
		}
		if got := errors.Is(tc.err, cause); got != tc.wrapsCause {
			t.Errorf("%T: errors.Is(cause) = %v, want %v", tc.err, got, tc.wrapsCause)
		}
	}
}
