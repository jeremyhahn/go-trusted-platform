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

package sdkclient

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestTransportOptions_NamedTransportsProduceOneOption(t *testing.T) {
	for _, transport := range []string{TransportUnix, TransportREST, TransportQUIC, TransportMCP} {
		opts := TransportOptions("/run/quicbaasd.sock", transport)
		if len(opts) != 1 {
			t.Fatalf("%s: got %d options, want 1", transport, len(opts))
		}
		if opts[0] == nil {
			t.Fatalf("%s: nil option", transport)
		}
	}
}

func TestTransportOptions_UnknownOrEmptyLetsTheSDKAutoDetect(t *testing.T) {
	for _, transport := range []string{"", "grpc", "carrier-pigeon"} {
		if opts := TransportOptions("127.0.0.1:9443", transport); opts != nil {
			t.Fatalf("%q: got %d options, want none", transport, len(opts))
		}
	}
}

func TestDial_EmptyAddressIsRefused(t *testing.T) {
	client, err := Dial("", "", nil)
	if err == nil {
		if client != nil {
			_ = client.Close()
		}
		t.Fatal("expected an error for an empty address")
	}
}

func TestDial_WithoutTLSIsRefusedBySDK(t *testing.T) {
	client, err := Dial("/run/does-not-exist.sock", TransportUnix, nil)
	if err == nil {
		_ = client.Close()
		t.Fatal("expected the SDK to refuse a connection without TLS")
	}
}

func TestDial_WithTLSBuildsAClient(t *testing.T) {
	client, err := Dial("127.0.0.1:1", "", &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
