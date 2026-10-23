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

package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// tlsPair completes a real TLS handshake over an in-memory pipe and
// returns both ends' connection states.
func tlsPair(t *testing.T, version uint16) (client, server tls.ConnectionState) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "binding-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"binding-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil {
			t.Logf("close client pipe: %v", err)
		}
		if err := serverConn.Close(); err != nil {
			t.Logf("close server pipe: %v", err)
		}
	})
	srv := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
	cli := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: "binding-test", MinVersion: version, MaxVersion: version})

	done := make(chan error, 1)
	go func() { done <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return cli.ConnectionState(), srv.ConnectionState()
}

// binderOf returns the ChannelBinder opt carries.
func binderOf(t *testing.T, opt grpc.CallOption) ChannelBinder {
	t.Helper()
	binder, ok := ChannelBindingFrom([]grpc.CallOption{opt})
	if !ok {
		t.Fatal("the option carries no channel binding")
	}
	return binder
}

func TestChannelBindingFrom(t *testing.T) {
	bind := func(context.Context, []byte) error { return nil }
	opts := []grpc.CallOption{grpc.WaitForReady(true), WithChannelBinding(bind)}

	if _, ok := ChannelBindingFrom(opts); !ok {
		t.Fatal("ChannelBindingFrom did not find the binding option")
	}
}

func TestChannelBindingFrom_Absent(t *testing.T) {
	if _, ok := ChannelBindingFrom([]grpc.CallOption{grpc.WaitForReady(true)}); ok {
		t.Fatal("ChannelBindingFrom found a binding where none was set")
	}
	if _, ok := ChannelBindingFrom([]grpc.CallOption{WithChannelBinding(nil)}); ok {
		t.Fatal("ChannelBindingFrom accepted a nil BindFunc")
	}
	bind := func(context.Context, []byte) error { return nil }
	if _, ok := ChannelBindingFrom([]grpc.CallOption{WithExportedChannelBinding(nil, bind)}); ok {
		t.Fatal("ChannelBindingFrom accepted a nil ExportFunc")
	}
}

func TestBindChannel_MatchesPeerExporter(t *testing.T) {
	client, server := tlsPair(t, tls.VersionTLS13)
	want, err := ExportChannelBinding(&server)
	if err != nil {
		t.Fatalf("server exporter: %v", err)
	}

	var got []byte
	err = BindChannel(context.Background(), "test", &client, binderOf(t, WithChannelBinding(func(_ context.Context, binding []byte) error {
		got = binding
		return nil
	})))
	if err != nil {
		t.Fatalf("BindChannel: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("client binding differs from the server's exporter for the same connection")
	}
}

func TestBindChannel_Refusals(t *testing.T) {
	client12, _ := tlsPair(t, tls.VersionTLS12)
	bindErr := errors.New("signer failed")
	tests := []struct {
		name  string
		state *tls.ConnectionState
	}{
		{name: "no connection state", state: nil},
		{name: "TLS 1.2", state: &client12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			err := BindChannel(context.Background(), "test", tt.state, binderOf(t, WithChannelBinding(func(context.Context, []byte) error {
				called = true
				return nil
			})))
			var unavailable *ErrChannelBindingUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want ErrChannelBindingUnavailable", err)
			}
			var unbound *ErrChannelUnbound
			if !errors.As(err, &unbound) {
				t.Fatalf("err = %v, want ErrChannelUnbound as the cause", err)
			}
			if called {
				t.Fatal("bind was called without a channel binding")
			}
		})
	}

	client13, _ := tlsPair(t, tls.VersionTLS13)
	err := BindChannel(context.Background(), "test", &client13, binderOf(t, WithChannelBinding(func(context.Context, []byte) error { return bindErr })))
	if !errors.Is(err, bindErr) {
		t.Fatalf("err = %v, want the BindFunc's error", err)
	}
}

// peerLabel stands in for an exporter label other than the default one.
const peerLabel = "EXPORTER-binding-test-peer"

func exportPeer(state *tls.ConnectionState) ([]byte, error) {
	return state.ExportKeyingMaterial(peerLabel, nil, ChannelBindingSize)
}

func TestBindChannel_UsesTheCallsExporter(t *testing.T) {
	client, server := tlsPair(t, tls.VersionTLS13)
	want, err := exportPeer(&server)
	if err != nil {
		t.Fatalf("server exporter: %v", err)
	}
	diskless, err := ExportChannelBinding(&server)
	if err != nil {
		t.Fatalf("default exporter: %v", err)
	}

	var got []byte
	binder := binderOf(t, WithExportedChannelBinding(exportPeer, func(_ context.Context, binding []byte) error {
		got = binding
		return nil
	}))
	if err := BindChannel(context.Background(), "test", &client, binder); err != nil {
		t.Fatalf("BindChannel: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the binding was not derived with the call's exporter")
	}
	if bytes.Equal(got, diskless) {
		t.Fatal("the binding was derived with the default exporter")
	}
}

func TestBindChannel_ExporterFailureIsUnavailable(t *testing.T) {
	exportErr := errors.New("exporter failed")
	called := false
	binder := binderOf(t, WithExportedChannelBinding(
		func(*tls.ConnectionState) ([]byte, error) { return nil, exportErr },
		func(context.Context, []byte) error { called = true; return nil },
	))
	err := BindChannel(context.Background(), "test", nil, binder)
	var unavailable *ErrChannelBindingUnavailable
	if !errors.As(err, &unavailable) || !errors.Is(err, exportErr) {
		t.Fatalf("err = %v, want ErrChannelBindingUnavailable caused by the exporter", err)
	}
	if called {
		t.Fatal("bind was called without a channel binding")
	}
}
