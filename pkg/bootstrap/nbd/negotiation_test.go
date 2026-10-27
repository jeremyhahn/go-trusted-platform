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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

func TestNegotiation_GoReportsTheExport(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
	replies := c.describe(optGo, testIdentity, infoName, infoBlockSize)

	if len(replies) != 4 {
		t.Fatalf("got %d replies, want INFO export, name, block size and ACK", len(replies))
	}
	export := replies[0].data
	if binary.BigEndian.Uint16(export[0:2]) != infoExport ||
		binary.BigEndian.Uint64(export[2:10]) != testVolumeSize ||
		binary.BigEndian.Uint16(export[10:12]) != exportFlags {
		t.Fatalf("export info = % x", export)
	}
	if name := string(replies[1].data[2:]); name != testIdentity {
		t.Fatalf("export name = %q", name)
	}
	block := replies[2].data
	if binary.BigEndian.Uint32(block[2:6]) != 1 ||
		binary.BigEndian.Uint32(block[6:10]) != preferredBlockSize ||
		binary.BigEndian.Uint32(block[10:14]) != maxPayload {
		t.Fatalf("block size info = % x", block)
	}
	if replies[3].replyType != repAck {
		t.Fatalf("final reply type = %#x", replies[3].replyType)
	}

	c.request(cmdDisc, 0, 1, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("session error = %v", err)
	}
}

func TestNegotiation_InfoDoesNotEnterTransmission(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
	if replies := c.describe(optInfo, ""); replies[len(replies)-1].replyType != repAck {
		t.Fatalf("INFO did not end with ACK: %+v", replies)
	}
	c.sendOption(optAbort, nil)
	if reply := c.readReply(); reply.replyType != repAck {
		t.Fatalf("ABORT reply type = %#x", reply.replyType)
	}
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("session error = %v", err)
	}
}

func TestNegotiation_ExportNameEntersTransmission(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	// Without NO_ZEROES the reply carries the 124 bytes of padding.
	c := dialClient(t, addr, clientFlagFixedNewstyle)
	c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
	c.sendOption(optExportName, []byte(testIdentity))
	reply := c.readFull(10 + zeroPadLength)
	if size := binary.BigEndian.Uint64(reply[0:8]); size != testVolumeSize {
		t.Fatalf("export size = %d", size)
	}

	c.request(cmdDisc, 0, 1, 0, 0, nil)
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("session error = %v", err)
	}
}

func TestNegotiation_PlaintextOptionIsRefused(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	replies := c.describe(optGo, "")
	if replies[0].replyType != repErrTLSReqd {
		t.Fatalf("plaintext GO reply type = %#x, want TLS_REQD", replies[0].replyType)
	}
	c.sendOption(optAbort, nil)
	c.readReply()

	var refused ErrTLSRequired
	if err := awaitResult(t, result); !errors.As(err, &refused) || refused.Option != optGo {
		t.Fatalf("session error = %v, want ErrTLSRequired for GO", err)
	}
}

func TestNegotiation_PlaintextExportNameClosesTheConnection(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.sendOption(optExportName, nil)

	if err := awaitResult(t, result); !errors.As(err, new(ErrTLSRequired)) {
		t.Fatalf("session error = %v, want ErrTLSRequired", err)
	}
	c.expectClosed()
}

func TestNegotiation_ClientLeavingAfterRefusalReportsIt(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.describe(optInfo, "")
	if err := c.conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := awaitResult(t, result); !errors.As(err, new(ErrTLSRequired)) {
		t.Fatalf("session error = %v, want ErrTLSRequired", err)
	}
}

func TestNegotiation_ClientLeavingWithoutRefusalIsAProtocolError(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	if err := c.conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
		t.Fatalf("session error = %v, want ErrProtocol", err)
	}
}

func TestNegotiation_HandshakeRefusals(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	stranger := testutil.GenerateTestTLSBundle(t)

	unreadable, err := trust.NewAnchor(trust.AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return nil, &trust.ErrAnchorUnavailable{Cause: os.ErrNotExist}
	}))
	if err != nil {
		t.Fatalf("NewAnchor: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		client  *tls.Config
		wantErr error
	}{
		{
			name:    "no client certificate",
			client:  clientTLS(bundle.CAPool, nil),
			wantErr: ErrClientCertificateRequired{},
		},
		{
			name:    "certificate from another CA",
			client:  clientTLS(bundle.CAPool, &stranger.ClientCert),
			wantErr: ErrClientCertificateUntrusted{},
		},
		{
			name:    "identity not registered",
			mutate:  func(cfg *Config) { cfg.Identities = []string{"other-device"} },
			client:  clientTLS(bundle.CAPool, &bundle.ClientCert),
			wantErr: ErrUnknownIdentity{},
		},
		{
			name:    "anchor unreadable",
			mutate:  func(cfg *Config) { cfg.Anchor = unreadable },
			client:  clientTLS(bundle.CAPool, &bundle.ClientCert),
			wantErr: ErrTrustAnchor{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, bundle)
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			addr, result := startSession(t, newTestServer(t, cfg))
			c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
			// The client handshake completes under TLS 1.3; the refusal
			// arrives as an alert on the first read.
			c.startTLS(tc.client)
			c.expectClosed()

			err := awaitResult(t, result)
			if !sameErrorType(err, tc.wantErr) {
				t.Fatalf("session error = %v, want %T", err, tc.wantErr)
			}
		})
	}
}

// sameErrorType reports whether err's chain holds an error of want's type.
func sameErrorType(err, want error) bool {
	switch want.(type) {
	case ErrClientCertificateRequired:
		return errors.As(err, new(ErrClientCertificateRequired))
	case ErrClientCertificateUntrusted:
		return errors.As(err, new(ErrClientCertificateUntrusted))
	case ErrUnknownIdentity:
		return errors.As(err, new(ErrUnknownIdentity))
	case ErrTrustAnchor:
		return errors.As(err, new(ErrTrustAnchor))
	default:
		return false
	}
}

func TestNegotiation_AnotherDevicesExportIsRefused(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	cfg.Identities = append(cfg.Identities, "other-device")

	t.Run("GO", func(t *testing.T) {
		addr, result := startSession(t, newTestServer(t, cfg))
		c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
		c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
		if replies := c.describe(optGo, "other-device"); replies[0].replyType != repErrPolicy {
			t.Fatalf("GO reply type = %#x, want POLICY", replies[0].replyType)
		}
		c.sendOption(optAbort, nil)
		c.readReply()

		var refused ErrExportNotPermitted
		err := awaitResult(t, result)
		if !errors.As(err, &refused) || refused.Identity != testIdentity || refused.Export != "other-device" {
			t.Fatalf("session error = %v, want ErrExportNotPermitted", err)
		}
	})
	t.Run("EXPORT_NAME", func(t *testing.T) {
		addr, result := startSession(t, newTestServer(t, cfg))
		c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
		c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
		c.sendOption(optExportName, []byte("other-device"))
		c.expectClosed()
		if err := awaitResult(t, result); !errors.As(err, new(ErrExportNotPermitted)) {
			t.Fatalf("session error = %v, want ErrExportNotPermitted", err)
		}
	})
	if _, err := cfg.Volumes.Attach("other-device"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the other device's volume was touched: %v", err)
	}
}

func TestNegotiation_OptionErrorsAfterTLS(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))

	c.sendOption(optStartTLS, nil)
	if reply := c.readReply(); reply.replyType != repErrInvalid {
		t.Fatalf("second STARTTLS reply type = %#x, want INVALID", reply.replyType)
	}
	c.sendOption(99, nil)
	if reply := c.readReply(); reply.replyType != repErrUnsup || reply.option != 99 {
		t.Fatalf("unknown option reply = %+v, want UNSUP", reply)
	}
	c.sendOption(optGo, []byte{0, 0, 0, 9})
	if reply := c.readReply(); reply.replyType != repErrInvalid {
		t.Fatalf("malformed GO reply type = %#x, want INVALID", reply.replyType)
	}
	c.sendOption(optAbort, nil)
	c.readReply()

	if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
		t.Fatalf("session error = %v, want the last refusal as ErrProtocol", err)
	}
}

func TestNegotiation_StartTLSWithDataIsRefused(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)

	c.sendOption(optStartTLS, []byte{1})
	if reply := c.readReply(); reply.replyType != repErrInvalid {
		t.Fatalf("STARTTLS with data reply type = %#x, want INVALID", reply.replyType)
	}
	c.sendOption(optAbort, nil)
	c.readReply()
	if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
		t.Fatalf("session error = %v, want ErrProtocol", err)
	}
}

func TestNegotiation_VolumeFailureIsAPlatformError(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	// A regular file where the volume directory should be.
	blocker := filepath.Join(t.TempDir(), "volumes")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg.Volumes = localVolumes(t, blocker)

	addr, result := startSession(t, newTestServer(t, cfg))
	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	c.startTLS(clientTLS(bundle.CAPool, &bundle.ClientCert))
	if replies := c.describe(optGo, ""); replies[0].replyType != repErrPlatform {
		t.Fatalf("GO reply type = %#x, want PLATFORM", replies[0].replyType)
	}
	if err := c.conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := awaitResult(t, result); !errors.As(err, new(ErrVolume)) {
		t.Fatalf("session error = %v, want ErrVolume", err)
	}
}

func TestNegotiation_MalformedOpeningIsRefused(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)

	t.Run("unknown client flags", func(t *testing.T) {
		addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
		dialClient(t, addr, clientFlagFixedNewstyle|0x80)
		var refused ErrUnsupportedClientFlags
		if err := awaitResult(t, result); !errors.As(err, &refused) || refused.Flags != clientFlagFixedNewstyle|0x80 {
			t.Fatalf("session error = %v, want ErrUnsupportedClientFlags", err)
		}
	})
	t.Run("not fixed newstyle", func(t *testing.T) {
		addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
		dialClient(t, addr, clientFlagNoZeroes)
		if err := awaitResult(t, result); !errors.As(err, new(ErrUnsupportedClientFlags)) {
			t.Fatalf("session error = %v, want ErrUnsupportedClientFlags", err)
		}
	})
	t.Run("bad option magic", func(t *testing.T) {
		addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
		c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
		c.write(make([]byte, 16))
		if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
			t.Fatalf("session error = %v, want ErrProtocol", err)
		}
	})
	t.Run("oversized option", func(t *testing.T) {
		addr, result := startSession(t, newTestServer(t, testConfig(t, bundle)))
		c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
		header := binary.BigEndian.AppendUint64(nil, optionMagic)
		header = binary.BigEndian.AppendUint32(header, optGo)
		header = binary.BigEndian.AppendUint32(header, maxOptionLength+1)
		c.write(header)
		if err := awaitResult(t, result); !errors.As(err, new(ErrProtocol)) {
			t.Fatalf("session error = %v, want ErrProtocol", err)
		}
	})
}

func TestNegotiation_SilentClientHitsTheHandshakeDeadline(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	cfg.HandshakeTimeout = 50 * time.Millisecond
	addr, result := startSession(t, newTestServer(t, cfg))

	dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	var timedOut ErrProtocol
	if err := awaitResult(t, result); !errors.As(err, &timedOut) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("session error = %v, want a deadline ErrProtocol", err)
	}
}

func TestParseInfoRequest(t *testing.T) {
	name, requests, ok := parseInfoRequest(infoRequest("node", infoName, infoBlockSize))
	if !ok || name != "node" || len(requests) != 2 || requests[1] != infoBlockSize {
		t.Fatalf("parseInfoRequest = %q %v %v", name, requests, ok)
	}

	malformed := map[string][]byte{
		"short":            {0, 0},
		"name past end":    {0, 0, 0, 9, 'a'},
		"missing count":    {0, 0, 0, 1, 'a'},
		"requests missing": {0, 0, 0, 0, 0, 2, 0, 1},
		"trailing bytes":   append(infoRequest("a"), 0),
	}
	for label, data := range malformed {
		if _, _, ok := parseInfoRequest(data); ok {
			t.Errorf("%s: parsed malformed data % x", label, data)
		}
	}
}
