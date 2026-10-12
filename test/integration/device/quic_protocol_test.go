//go:build integration

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

package device

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// These tests exist because the device QUIC adapter was green for as long as
// it existed while reaching no handler at all. It wrote a JSON
// {method, path, body} envelope; the daemon reads binary opcode framing. Every
// call failed, and the suite's substring skip guard turned each failure into
// "not implemented".
//
// The assertion that separates a working adapter from that one is not "the
// call returned an error" - a broken adapter errors too. It is that the
// DAEMON ANSWERED: a response frame came back carrying a status byte. Only an
// adapter speaking the server's framing can produce ErrQUICStatus, so every
// negative case below asserts that type rather than merely a non-nil error.

// quicNegativeTimeout bounds each negative probe.
const quicNegativeTimeout = 30 * time.Second

// requireDaemonAnswered fails unless err is a status the daemon sent back.
// A transport-level failure (no ALPN, wrong framing, no connection) surfaces
// as QUICAdapterError and is exactly what this must not accept.
func requireDaemonAnswered(t *testing.T, op string, err error) ErrQUICStatus {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected the daemon to refuse, got success", op)
	}
	var status ErrQUICStatus
	if !errors.As(err, &status) {
		t.Fatalf("%s: no response frame came back from the daemon, so the adapter did not reach a handler: %v",
			op, err)
	}
	return status
}

// newConnectedQUICAdapter dials the daemon or fails the test. A handshake
// failure here is the ALPN defect (the adapter offered "device-quic" while
// the listener offers only "platform-quic"), not an absent daemon.
func newConnectedQUICAdapter(t *testing.T, ctx context.Context) *QUICAdapter {
	t.Helper()
	adapter := NewQUICAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Fatalf("QUIC setup failed; the adapter must negotiate ALPN %q and reach the daemon: %v",
			quicALPN, err)
	}
	t.Cleanup(func() {
		if err := adapter.Teardown(context.Background()); err != nil {
			t.Logf("teardown: %v", err)
		}
	})
	return adapter
}

// TestQUICAdapterALPNMatchesTheServer pins the one string that decides
// whether a handshake can complete at all. The expected value is read from
// the server's own TLS configuration rather than typed here, so the two
// cannot drift.
func TestQUICAdapterALPNMatchesTheServer(t *testing.T) {
	SkipIfNotIntegration(t)

	// The server's own TLS configuration, built the way the daemon builds
	// it, is the reference. Reading it here rather than retyping the string
	// is what keeps the two from drifting.
	serverTLS, err := quicapi.GenerateSelfSignedTLSConfig()
	if err != nil {
		t.Fatalf("build the server TLS configuration: %v", err)
	}
	if len(serverTLS.NextProtos) != 1 || serverTLS.NextProtos[0] != quicwire.ALPNProtocol {
		t.Fatalf("the server's TLS configuration advertises %v, not [%s]; the constant and the "+
			"configuration have drifted", serverTLS.NextProtos, quicwire.ALPNProtocol)
	}

	adapter := NewQUICAdapter()
	got := adapter.tlsConfig.NextProtos
	if len(got) != 1 || got[0] != serverTLS.NextProtos[0] {
		t.Fatalf("adapter offers ALPN %v, server offers %v; disjoint sets fail the handshake "+
			"with no_application_protocol before a stream is opened", got, serverTLS.NextProtos)
	}
}

// TestQUICWrongALPNFailsTheHandshake is the other half of the ALPN fix: not
// only does the adapter now offer the right protocol, offering a wrong one
// fails closed. The dial must not succeed, because a connection that comes up
// on an unnegotiated protocol is how the original defect stayed invisible -
// every subsequent call failed with text the skip guard laundered.
//
// This is the one caller that passes an explicit protocol to
// helpers.QUICTLSConfig. The override exists for exactly this: a helper that
// makes the bug unconstructible must not also make the test for it
// unwritable.
func TestQUICWrongALPNFailsTheHandshake(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), quicNegativeTimeout)
	defer cancel()

	tlsConfig := helpers.QUICTLSConfig("device-quic")
	conn, err := quicgo.DialAddr(ctx, helpers.GetQUICEndpoint(), tlsConfig, &quicgo.Config{})
	if err == nil {
		_ = conn.CloseWithError(0, "unexpected success")
		t.Fatal("the daemon accepted ALPN \"device-quic\", which no listener advertises; " +
			"a wrong protocol must fail the handshake, not open a stream nothing reads")
	}
	t.Logf("wrong ALPN refused at the handshake, as it must be: %v", err)
}

// TestQUICDeviceOperationsReachTheDaemon drives one negative case per
// implemented opcode. Each asserts a refusal that ONLY a daemon can send.
func TestQUICDeviceOperationsReachTheDaemon(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), quicNegativeTimeout)
	defer cancel()
	adapter := newConnectedQUICAdapter(t, ctx)

	// An id no device has. Every read path must answer not-found.
	const absentID = "18446744073709551615"

	t.Run("GetDevice/unknown id", func(t *testing.T) {
		_, err := adapter.GetDevice(ctx, GetDeviceOptions{DeviceID: absentID})
		status := requireDaemonAnswered(t, "GetDevice", err)
		if status.Status != quicwire.StatusNotFound {
			t.Errorf("expected StatusNotFound (0x%02X), got 0x%02X: %s",
				quicwire.StatusNotFound, status.Status, status.Message)
		}
	})

	t.Run("UpdateDevice/unknown id", func(t *testing.T) {
		_, err := adapter.UpdateDevice(ctx, UpdateDeviceOptions{DeviceID: absentID, Model: "nope"})
		requireDaemonAnswered(t, "UpdateDevice", err)
	})

	t.Run("DeleteDevice/unknown id", func(t *testing.T) {
		_, err := adapter.DeleteDevice(ctx, DeleteDeviceOptions{DeviceID: absentID})
		requireDaemonAnswered(t, "DeleteDevice", err)
	})

	t.Run("FindBySerial/unknown serial", func(t *testing.T) {
		_, err := adapter.FindBySerial(ctx, FindBySerialOptions{Serial: "SN-DOES-NOT-EXIST-480"})
		requireDaemonAnswered(t, "FindBySerial", err)
	})

	t.Run("RegisterDevice/no serial", func(t *testing.T) {
		_, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{Model: "no-serial-480"})
		requireDaemonAnswered(t, "RegisterDevice", err)
	})

	t.Run("GetProfile/unknown id", func(t *testing.T) {
		_, err := adapter.GetProfile(ctx, GetProfileOptions{ProfileID: absentID})
		requireDaemonAnswered(t, "GetProfile", err)
	})

	t.Run("UpdateProfile/unknown id", func(t *testing.T) {
		_, err := adapter.UpdateProfile(ctx, UpdateProfileOptions{ProfileID: absentID, Name: "nope"})
		requireDaemonAnswered(t, "UpdateProfile", err)
	})

	t.Run("DeleteProfile/unknown id", func(t *testing.T) {
		_, err := adapter.DeleteProfile(ctx, DeleteProfileOptions{ProfileID: absentID})
		requireDaemonAnswered(t, "DeleteProfile", err)
	})

	// CreateProfile has no natural refusal either: the daemon accepts a
	// profile carrying no name, measured against a live daemon on 2026-09-06.
	// Whether it should is a question for the service, not this transport, so
	// reachability is proved by a decoded reply rather than by a refusal that
	// does not exist. A non-functioning adapter can produce neither.
	t.Run("CreateProfile/decodes a reply frame", func(t *testing.T) {
		result, err := adapter.CreateProfile(ctx, CreateProfileOptions{Model: "no-name-480"})
		if err != nil {
			requireDaemonAnswered(t, "CreateProfile", err)
			return
		}
		if result == nil || result.Profile == nil {
			t.Fatal("CreateProfile returned neither a profile nor an error")
		}
		t.Cleanup(func() {
			_, _ = adapter.DeleteProfile(context.Background(), DeleteProfileOptions{
				ProfileID: strconv.FormatUint(result.Profile.ID, 10),
			})
		})
	})

	t.Run("AssignProfileToDevice/unknown profile", func(t *testing.T) {
		_, err := adapter.AssignProfileToDevice(ctx, AssignProfileToDeviceOptions{
			ProfileID: absentID,
			EKSerial:  "EK-DOES-NOT-EXIST-480",
		})
		requireDaemonAnswered(t, "AssignProfileToDevice", err)
	})

	// RecordAttestCert travels under the same category opcode (0xCF) on
	// sub-opcode 0x22. It reached the daemon on no transport here before
	// this change: it was the last method still writing the JSON envelope.
	t.Run("RecordAttestCert/unknown device", func(t *testing.T) {
		_, err := adapter.RecordAttestCert(ctx, RecordAttestCertOptions{DeviceID: absentID})
		requireDaemonAnswered(t, "RecordAttestCert", err)
	})

	// ListDevices and ListProfiles have no natural refusal - an empty page
	// is a valid answer - so they are proved by a decoded reply instead. A
	// non-functioning adapter cannot decode one.
	t.Run("ListDevices/decodes a reply frame", func(t *testing.T) {
		result, err := adapter.ListDevices(ctx, ListDevicesOptions{Limit: 1})
		if err != nil {
			requireDaemonAnswered(t, "ListDevices", err)
			return
		}
		if result == nil {
			t.Fatal("ListDevices returned neither a result nor an error")
		}
	})

	t.Run("ListProfiles/decodes a reply frame", func(t *testing.T) {
		result, err := adapter.ListProfiles(ctx, ListProfilesOptions{Limit: 1})
		if err != nil {
			requireDaemonAnswered(t, "ListProfiles", err)
			return
		}
		if result == nil {
			t.Fatal("ListProfiles returned neither a result nor an error")
		}
	})
}

// TestQUICDeviceAttestRefusesUnsignedEvidence carries #520's assertion onto
// this transport: a device must never come back verified on evidence whose
// signature signs nothing.
//
// It could not run on QUIC before #480. The adapter reached no handler, so
// AttestDevice returned ErrAttestationTransportUnavailable and the
// multiprotocol suite logged an absent surface instead of a verdict. The
// evidence comes from the same forgedQuoteEvidence helper the other
// transports use, so all six assert against one payload shape.
func TestQUICDeviceAttestRefusesUnsignedEvidence(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), quicNegativeTimeout)
	defer cancel()
	adapter := newConnectedQUICAdapter(t, ctx)

	registered, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
		Serial: GenerateTestSerial("quic-attest-480"),
		Model:  "test-model-quic-attest",
	})
	if err != nil {
		// Measured 2026-09-06: DeviceService.CreateDevice refuses every
		// registration with InvalidArgument "invalid device ID", on gRPC and
		// Unix exactly as here, so this is a service defect and not a
		// transport one. The assertion below is deliberately NOT relaxed to
		// accommodate it: a setup that cannot run must fail loudly, which is
		// the whole disagreement this suite is settling.
		t.Fatalf("RegisterDevice failed, so the negative case cannot run "+
			"(the daemon refuses registration on every transport, not just this one): %v", err)
	}
	deviceID := registered.Device.ID
	t.Cleanup(func() {
		_, _ = adapter.DeleteDevice(context.Background(), DeleteDeviceOptions{
			DeviceID: strconv.FormatUint(deviceID, 10),
		})
	})

	result, err := adapter.AttestDevice(ctx, AttestDeviceOptions{
		DeviceID: strconv.FormatUint(deviceID, 10),
		Evidence: forgedQuoteEvidence(t, "480"),
	})

	if err != nil {
		// A refusal to evaluate is the right answer, but it has to have
		// come from the daemon.
		requireDaemonAnswered(t, "AttestDevice", err)
		return
	}
	if result == nil {
		t.Fatal("AttestDevice returned neither a verdict nor an error")
	}
	if result.Verified {
		t.Fatalf("QUIC reported a device verified on a quote that is not a TPM quote: %+v", result)
	}
	if result.SignatureValid {
		t.Errorf("QUIC reported signature_valid=true for a signature over nothing: %+v", result)
	}
}
