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

//go:build integration

// Package provision provides multi-protocol integration tests for the
// config-delivery provisioning service (platform.v1 ConfigDeliveryService).
// The suite drives platformctl and the SDK provision client across all six
// protocols (CLI, REST, gRPC, QUIC, MCP, Unix) against a running platformd
// and asserts identical semantics: nonce issuance and single-use
// consumption, in-service EAB authentication, the delivered-vs-pending
// tri-state, and consistent typed-error mapping.
//
// TestProvisionDeliveredConfigLifecycle additionally activates the full
// delivered-config lifecycle: it seeds a real EAB credential and a device
// profile (bound to a synthetic EK serial / MAC, carrying a real config,
// and PRESTAGED with a synthetic hardware EK certificate) through the
// platform's own gRPC surfaces, then asserts the EK-bound matched-profile
// delivery contract (delivered with content equality; mismatched presented
// certificates rejected by the typed EK-binding gate), the refusal of the
// profile-bound credential for an identity that resolves to no profile
// (no pending session is opened), and the EK-bound SignDigest contract (signed, or the typed
// signer-unavailable when no CP DB key signer is wired) on every
// transport.
//
// Run via:
//
//	make integration-test-provision
package provision

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// callTimeout bounds each individual protocol call.
	callTimeout = 30 * time.Second

	// testEABKeyID is a deliberately unknown EAB key ID. With the EAB
	// service wired (QuicBaaS-backed daemon) it is rejected with an EAB
	// auth error; without an EAB service the request proceeds to profile
	// resolution and yields a pending session for an unknown device.
	testEABKeyID = "provision-mp-test-key"

	// testEABHMAC is the base64url (unpadded) encoding of
	// "provision-mp-test-hmac-key-0001".
	testEABHMAC = "cHJvdmlzaW9uLW1wLXRlc3QtaG1hYy1rZXktMDAwMQ"

	// unknownProfileID is a profile ID that never exists in the test
	// daemon (uint64 max), used to exercise the profile-not-found path.
	unknownProfileID = ^uint64(0)
)

// TestProvisionMultiProtocol runs the same scenario against every transport.
func TestProvisionMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	// CLI: session verbs only — the CLI's pre-enrollment verbs
	// (fetch-config / interactive) are raw-HTTP install-time flows by
	// design, not daemon-transport commands.
	t.Run("CLI", func(t *testing.T) {
		adapter := NewCLIAdapter()
		if err := adapter.Setup(ctx); err != nil {
			t.Fatalf("CLI setup failed: %v", err)
		}
		t.Cleanup(func() {
			if err := adapter.Teardown(); err != nil {
				t.Logf("Warning: CLI teardown error: %v", err)
			}
		})
		runSessionScenario(t, ctx, adapter)
	})

	// SDK transports: full pre-enrollment + session surface.
	adapters := []*SDKAdapter{
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("%s setup failed: %v", adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: %s teardown error: %v", adapter.Name(), err)
				}
			})
			runPreEnrollmentScenario(t, ctx, adapter)
			runSessionScenario(t, ctx, adapter)
		})
	}
}

// fetchNonce issues a nonce, failing the test on error.
func fetchNonce(t *testing.T, ctx context.Context, cmd ProvisionCommands) string {
	t.Helper()
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	nonce, err := cmd.GetNonce(callCtx)
	if err != nil {
		t.Fatalf("GetNonce failed: %v", err)
	}
	if nonce == "" {
		t.Fatal("GetNonce returned an empty nonce")
	}
	return nonce
}

// unknownDeviceRequest builds a FetchConfig request for a device identity
// that cannot match any profile, using the shared test EAB credentials.
func unknownDeviceRequest(ekSerial, nonce string) *platformv1.FetchConfigRequest {
	return &platformv1.FetchConfigRequest{
		EkSerial: ekSerial,
		EabKeyId: testEABKeyID,
		EabHmac:  testEABHMAC,
		Nonce:    nonce,
	}
}

// attemptUnknownDeviceFetch performs a FetchConfig for an unknown device
// with a fresh nonce and asserts one of the two legitimate outcomes:
//
//   - EAB enforced (EAB service wired): an EAB auth error — returns "".
//   - EAB not enforced: a pending session (never a delivered config for an
//     unknown device) — returns the session ID.
//
// Any other outcome fails the test.
func attemptUnknownDeviceFetch(t *testing.T, ctx context.Context, cmd ProvisionCommands, ekSerial string) string {
	t.Helper()
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	nonce := fetchNonce(t, ctx, cmd)
	resp, err := cmd.FetchConfig(callCtx, unknownDeviceRequest(ekSerial, nonce))
	if err != nil {
		if !isEABAuthError(err) {
			t.Fatalf("unexpected FetchConfig error for unknown device (want EAB auth error): %v", err)
		}
		return ""
	}

	pending := resp.GetPending()
	if pending == nil {
		t.Fatalf("unknown device must never receive a delivered config: %+v", resp)
	}
	if pending.GetSessionId() == "" {
		t.Fatal("pending response has empty session_id")
	}
	if !strings.Contains(pending.GetProvisionUrl(), pending.GetSessionId()) {
		t.Fatalf("provision_url %q does not contain session_id %q",
			pending.GetProvisionUrl(), pending.GetSessionId())
	}
	if pending.GetPollIntervalSeconds() <= 0 {
		t.Fatalf("poll_interval_seconds must be positive, got %d", pending.GetPollIntervalSeconds())
	}
	return pending.GetSessionId()
}

// runPreEnrollmentScenario exercises nonce issuance, request validation,
// EAB authentication, nonce single-use semantics, and (when a pending
// session can be created) the session fulfillment lifecycle.
func runPreEnrollmentScenario(t *testing.T, ctx context.Context, cmd ProvisionCommands) {
	t.Helper()

	t.Run("GetNonce", func(t *testing.T) {
		first := fetchNonce(t, ctx, cmd)
		if len(first) != 64 {
			t.Fatalf("expected 64-char hex nonce, got %d chars: %q", len(first), first)
		}
		second := fetchNonce(t, ctx, cmd)
		if first == second {
			t.Fatal("consecutive nonces must be unique")
		}
	})

	t.Run("GetNonceConcurrent", func(t *testing.T) {
		// Concurrent nonce requests must all produce unique nonces
		// (migrated from the legacy suite's load test).
		const concurrency = 10
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		type result struct {
			nonce string
			err   error
		}
		results := make(chan result, concurrency)
		for i := 0; i < concurrency; i++ {
			go func() {
				nonce, err := cmd.GetNonce(callCtx)
				results <- result{nonce: nonce, err: err}
			}()
		}

		seen := make(map[string]struct{}, concurrency)
		for i := 0; i < concurrency; i++ {
			select {
			case r := <-results:
				if r.err != nil {
					t.Fatalf("concurrent GetNonce failed: %v", r.err)
				}
				if r.nonce == "" {
					t.Fatal("concurrent GetNonce returned empty nonce")
				}
				if _, dup := seen[r.nonce]; dup {
					t.Fatalf("duplicate nonce under concurrent load: %s", r.nonce)
				}
				seen[r.nonce] = struct{}{}
			case <-callCtx.Done():
				t.Fatalf("timed out waiting for concurrent nonce results: %v", callCtx.Err())
			}
		}
	})

	t.Run("FetchConfigValidation", func(t *testing.T) {
		// Every credential/identity permutation must be rejected with an
		// invalid-argument error before the nonce is even consulted
		// (migrated from the legacy REST-only provisioning suite, now
		// asserted on every transport).
		tests := []struct {
			name string
			req  *platformv1.FetchConfigRequest
		}{
			{"missing EAB credentials", &platformv1.FetchConfigRequest{
				EkSerial: uniqueID("provision-mp-validation"),
				Nonce:    "irrelevant",
			}},
			{"missing nonce", &platformv1.FetchConfigRequest{
				EkSerial: uniqueID("provision-mp-validation"),
				EabKeyId: testEABKeyID,
				EabHmac:  testEABHMAC,
			}},
			{"missing eab_key_id", &platformv1.FetchConfigRequest{
				EkSerial: uniqueID("provision-mp-validation"),
				EabHmac:  testEABHMAC,
				Nonce:    "irrelevant",
			}},
			{"missing eab_hmac", &platformv1.FetchConfigRequest{
				EkSerial: uniqueID("provision-mp-validation"),
				EabKeyId: testEABKeyID,
				Nonce:    "irrelevant",
			}},
			{"missing device identity", &platformv1.FetchConfigRequest{
				EabKeyId: testEABKeyID,
				EabHmac:  testEABHMAC,
				Nonce:    "irrelevant",
			}},
			{"empty request", &platformv1.FetchConfigRequest{}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				callCtx, cancel := context.WithTimeout(ctx, callTimeout)
				defer cancel()
				_, err := cmd.FetchConfig(callCtx, tt.req)
				if err == nil {
					t.Fatal("invalid FetchConfig request must fail")
				}
				if !isInvalidArgument(err) {
					t.Fatalf("expected invalid-argument error, got: %v", err)
				}
			})
		}
	})

	t.Run("FetchConfigUnknownDevice", func(t *testing.T) {
		sessionID := attemptUnknownDeviceFetch(t, ctx, cmd, uniqueID("provision-mp-unknown"))
		if sessionID != "" {
			t.Logf("pending session created (EAB not enforced in this environment): %s", sessionID)
		}
	})

	t.Run("FetchConfigMACOnly", func(t *testing.T) {
		// A device identified only by MAC address (no TPM EK) must also
		// create a pending session carrying that MAC (migrated from the
		// legacy suite).
		mac := uniqueMAC()
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		nonce := fetchNonce(t, ctx, cmd)
		resp, err := cmd.FetchConfig(callCtx, &platformv1.FetchConfigRequest{
			MacAddress: mac,
			EabKeyId:   testEABKeyID,
			EabHmac:    testEABHMAC,
			Nonce:      nonce,
		})
		if err != nil {
			if !isEABAuthError(err) {
				t.Fatalf("unexpected FetchConfig error for MAC-only device: %v", err)
			}
			t.Log("EAB enforced: MAC-only pending session exercised via error-path coverage only")
			return
		}
		pending := resp.GetPending()
		if pending == nil {
			t.Fatalf("unknown MAC-only device must never receive a delivered config: %+v", resp)
		}

		session, err := cmd.GetSession(callCtx, pending.GetSessionId())
		if err != nil {
			t.Fatalf("GetSession(%s) failed: %v", pending.GetSessionId(), err)
		}
		if session.GetMacAddress() != mac {
			t.Fatalf("session mac_address = %q, want %q", session.GetMacAddress(), mac)
		}
		if session.GetEkSerial() != "" {
			t.Fatalf("session ek_serial must be empty for MAC-only identity, got %q", session.GetEkSerial())
		}
	})

	t.Run("DuplicateDeviceSeparateSessions", func(t *testing.T) {
		// Repeated config requests for the same device identity must
		// create separate sessions with unique IDs (migrated from the
		// legacy suite).
		ekSerial := uniqueID("provision-mp-dup")
		first := attemptUnknownDeviceFetch(t, ctx, cmd, ekSerial)
		if first == "" {
			t.Log("EAB enforced: duplicate-session behavior exercised via error-path coverage only")
			return
		}
		second := attemptUnknownDeviceFetch(t, ctx, cmd, ekSerial)
		if second == "" {
			t.Fatal("second fetch for the same device unexpectedly rejected")
		}
		if first == second {
			t.Fatalf("duplicate config requests must create separate sessions, both = %s", first)
		}
	})

	t.Run("NonceSingleUse", func(t *testing.T) {
		nonce := fetchNonce(t, ctx, cmd)

		// First use consumes the nonce regardless of the EAB outcome
		// (the nonce is validated and deleted before EAB validation).
		firstCtx, firstCancel := context.WithTimeout(ctx, callTimeout)
		defer firstCancel()
		resp, err := cmd.FetchConfig(firstCtx, unknownDeviceRequest(uniqueID("provision-mp-replay"), nonce))
		if err != nil && !isEABAuthError(err) {
			t.Fatalf("unexpected first-use error (want EAB auth error or pending): %v", err)
		}
		if err == nil && resp.GetPending() == nil {
			t.Fatalf("unknown device must never receive a delivered config: %+v", resp)
		}

		// Replaying the same nonce must be rejected as spent.
		secondCtx, secondCancel := context.WithTimeout(ctx, callTimeout)
		defer secondCancel()
		_, err = cmd.FetchConfig(secondCtx, unknownDeviceRequest(uniqueID("provision-mp-replay"), nonce))
		if err == nil {
			t.Fatal("nonce replay must fail")
		}
		if !isNonceSpent(err) {
			t.Fatalf("expected spent-nonce error, got: %v", err)
		}
	})

	t.Run("SessionLifecycle", func(t *testing.T) {
		ekSerial := uniqueID("provision-mp-lifecycle")
		sessionID := attemptUnknownDeviceFetch(t, ctx, cmd, ekSerial)
		if sessionID == "" {
			// EAB is enforced, so the deliberately unknown credential is
			// rejected before a session can be created — that rejection IS
			// the authentication contract exercised here. A seeded,
			// profile-bound credential cannot open one either: that
			// refusal is asserted by TestProvisionDeliveredConfigLifecycle.
			t.Log("EAB enforced: pending-session lifecycle exercised via error-path coverage only")
			return
		}
		runPendingSessionLifecycle(t, ctx, cmd, sessionID, ekSerial)
	})
}

// runPendingSessionLifecycle drives a freshly created pending session
// through get/list/poll/fulfill and asserts state transitions.
func runPendingSessionLifecycle(t *testing.T, ctx context.Context, cmd ProvisionCommands, sessionID, ekSerial string) {
	t.Helper()

	callCtx, cancel := context.WithTimeout(ctx, 2*callTimeout)
	defer cancel()

	session, err := cmd.GetSession(callCtx, sessionID)
	if err != nil {
		t.Fatalf("GetSession(%s) failed: %v", sessionID, err)
	}
	if session.GetEkSerial() != ekSerial {
		t.Fatalf("session ek_serial = %q, want %q", session.GetEkSerial(), ekSerial)
	}
	if session.GetFulfilled() {
		t.Fatal("freshly created session must not be fulfilled")
	}
	if session.GetCreatedAt() == nil || session.GetExpiresAt() == nil {
		t.Fatalf("session must carry created_at and expires_at, got %v / %v",
			session.GetCreatedAt(), session.GetExpiresAt())
	}
	if !session.GetExpiresAt().AsTime().After(session.GetCreatedAt().AsTime()) {
		t.Fatalf("expires_at (%v) must be after created_at (%v)",
			session.GetExpiresAt().AsTime(), session.GetCreatedAt().AsTime())
	}

	sessions, err := cmd.ListSessions(callCtx)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	found := false
	for _, s := range sessions {
		if s.GetId() == sessionID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("session %s not present in ListSessions result", sessionID)
	}

	poll, err := cmd.PollSession(callCtx, sessionID)
	if err != nil {
		t.Fatalf("PollSession(%s) failed: %v", sessionID, err)
	}
	if poll.GetDelivered() != nil {
		t.Fatal("unfulfilled session must poll as pending, got delivered config")
	}
	if status := poll.GetPendingStatus(); status != "pending" {
		t.Fatalf("pending_status = %q, want %q", status, "pending")
	}

	// Fulfilling with a nonexistent profile: with the profile service
	// wired this is a not-found rejection; without one the service
	// records the bare profile ID and marks the session fulfilled.
	fulfillResp, err := cmd.FulfillSession(callCtx, sessionID, unknownProfileID)
	if err != nil {
		if !isNotFound(err) {
			t.Fatalf("expected profile-not-found error, got: %v", err)
		}
		return
	}
	if fulfillResp.GetStatus() != "fulfilled" {
		t.Fatalf("fulfill status = %q, want %q", fulfillResp.GetStatus(), "fulfilled")
	}

	session, err = cmd.GetSession(callCtx, sessionID)
	if err != nil {
		t.Fatalf("GetSession after fulfill failed: %v", err)
	}
	if !session.GetFulfilled() {
		t.Fatal("session must be fulfilled after FulfillSession")
	}

	// A session fulfilled through the profile-less path carries no resolved
	// profile, so polling it cannot deliver a config: every transport must
	// surface the typed invalid-state error (configdelivery
	// ErrSessionProfileMissing) instead of crashing on the nil profile.
	if _, err := cmd.PollSession(callCtx, sessionID); err == nil {
		t.Fatal("polling a fulfilled session without a resolved profile must fail")
	} else if !isProfileMissing(err) {
		t.Fatalf("expected profile-missing invalid-state error, got: %v", err)
	}

	// Double-fulfill must be rejected.
	if _, err := cmd.FulfillSession(callCtx, sessionID, unknownProfileID); err == nil {
		t.Fatal("fulfilling an already-fulfilled session must fail")
	} else if !isAlreadyFulfilled(err) {
		t.Fatalf("expected already-fulfilled error, got: %v", err)
	}
}

// runSessionScenario exercises the session verbs shared by every adapter
// (including the CLI): list success and consistent not-found error mapping
// for unknown sessions on get, poll, and fulfill.
func runSessionScenario(t *testing.T, ctx context.Context, cmd SessionCommands) {
	t.Helper()

	t.Run("ListSessions", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		if _, err := cmd.ListSessions(callCtx); err != nil {
			t.Fatalf("ListSessions failed: %v", err)
		}
	})

	t.Run("GetSessionNotFound", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		_, err := cmd.GetSession(callCtx, uniqueID("provision-mp-missing"))
		if err == nil {
			t.Fatal("GetSession for an unknown session must fail")
		}
		if !isNotFound(err) {
			t.Fatalf("expected not-found error, got: %v", err)
		}
	})

	t.Run("PollSessionNotFound", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		_, err := cmd.PollSession(callCtx, uniqueID("provision-mp-missing"))
		if err == nil {
			t.Fatal("PollSession for an unknown session must fail")
		}
		if !isNotFound(err) {
			t.Fatalf("expected not-found error, got: %v", err)
		}
	})

	t.Run("FulfillSessionNotFound", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		_, err := cmd.FulfillSession(callCtx, uniqueID("provision-mp-missing"), 1)
		if err == nil {
			t.Fatal("FulfillSession for an unknown session must fail")
		}
		if !isNotFound(err) {
			t.Fatalf("expected not-found error, got: %v", err)
		}
	})
}

// TestProvisionDeliveredConfigLifecycle exercises the full delivered-config
// lifecycle against every transport using REAL daemon-side state seeded
// through the platform's own surfaces: a device profile created via the
// platform.v1 DeviceService (bound to a synthetic EK serial / MAC and
// carrying a real platform config) and an active EAB credential created via
// the platform.v1 EABService. Seeding uses the gRPC transport (seeding is
// setup, not the operation under test); the lifecycle operations then run
// through the adapter under test on each transport.
func TestProvisionDeliveredConfigLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	fixture := seedLifecycleFixture(t, ctx)

	// SDK transports only: the CLI has no daemon-transport fetch verb, and a
	// pending session for it to fulfill cannot be staged while the EAB
	// service is wired (UnknownDeviceRefused).
	adapters := []*SDKAdapter{
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("%s setup failed: %v", adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: %s teardown error: %v", adapter.Name(), err)
				}
			})
			runDeliveredConfigScenario(t, ctx, adapter, fixture)
		})
	}
}

// runDeliveredConfigScenario drives the delivered-config coverage on a
// single SDK transport: the matched-profile FetchConfig contract, the
// refusal of the profile-bound credential for an unknown device, and the
// SignDigest authentication gates. Every subtest consumes its own
// single-use nonce.
func runDeliveredConfigScenario(t *testing.T, ctx context.Context, cmd ProvisionCommands, fixture *lifecycleFixture) {
	t.Helper()

	t.Run("FetchConfigMatchedProfile", func(t *testing.T) {
		// Valid nonce + valid EAB + an identity matching the seeded
		// profile + the presented EK certificate matching the profile's
		// PRESTAGED EK certificate. The fixture prestages the certificate
		// over the wire (DeviceProfile.ek_cert on CreateProfile), so with
		// RequireEKMatch enforced the EK-bound delivered path is now
		// REACHABLE and must complete: any error, pending session, or
		// config mismatch fails the test. This is the end-to-end contract
		// the hardware-EK prestage feature exists for.
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		nonce := fetchNonce(t, ctx, cmd)
		resp, err := cmd.FetchConfig(callCtx,
			fixture.fetchRequest(fixture.ekSerial, fixture.macAddress, nonce))
		if err != nil {
			t.Fatalf("EK-bound matched-profile fetch must deliver, got: %v", err)
		}

		if resp.GetPending() != nil {
			t.Fatalf("matched profile must never yield a pending session: %+v", resp)
		}
		delivered := resp.GetDelivered()
		if delivered == nil {
			t.Fatalf("expected delivered config, got: %+v", resp)
		}
		if delivered.GetStatus() != "ok" {
			t.Fatalf("delivered status = %q, want %q", delivered.GetStatus(), "ok")
		}
		if err := assertConfigJSONEqual(delivered.GetConfigJson(), fixture.config); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("FetchConfigEKMismatch", func(t *testing.T) {
		// Same authentication, matched identity, but the presented EK
		// certificate belongs to a DIFFERENT key pair than the prestaged
		// one: the request must authenticate (nonce consumed, EAB
		// accepted, profile matched) and then be rejected by the typed
		// EK-binding gate — never delivered, never pending.
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		_, mismatchB64DER := newSelfSignedEKCert(t)
		nonce := fetchNonce(t, ctx, cmd)
		req := fixture.fetchRequest(fixture.ekSerial, fixture.macAddress, nonce)
		req.EkCert = mismatchB64DER

		resp, err := cmd.FetchConfig(callCtx, req)
		if err == nil {
			t.Fatalf("mismatched EK certificate must be rejected, got: %+v", resp)
		}
		if !isEKBindingRejected(err) {
			t.Fatalf("expected typed EK-binding rejection, got: %v", err)
		}
	})

	t.Run("UnknownDeviceRefused", func(t *testing.T) {
		// A credential names the profile it was issued for, so a device
		// presenting it under an identity that resolves to no profile is
		// not that device: it is refused with the typed
		// ErrEABProfileMismatch and never opens a pending session
		// (docs/provisioning/config-delivery.md, EAB Credential Binding).
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		ekSerial := uniqueID("provision-mp-unbound")
		nonce := fetchNonce(t, ctx, cmd)
		resp, err := cmd.FetchConfig(callCtx, fixture.fetchRequest(ekSerial, "", nonce))
		if err == nil {
			t.Fatalf("a profile-bound credential must be refused for an unknown device, got: %+v", resp)
		}
		if !isEABProfileMismatch(err) {
			t.Fatalf("expected typed EAB profile-binding rejection, got: %v", err)
		}

		sessions, err := cmd.ListSessions(callCtx)
		if err != nil {
			t.Fatalf("ListSessions failed: %v", err)
		}
		for _, session := range sessions {
			if session.GetEkSerial() == ekSerial {
				t.Fatalf("refused fetch opened pending session %s", session.GetId())
			}
		}
	})

	t.Run("SignDigest", func(t *testing.T) {
		// Same authentication as FetchConfig plus the DB-signer gate. The
		// fixture prestages the EK certificate AND presents the matching
		// one, so the EK-binding gate PASSES and exactly two outcomes
		// remain legitimate, both fully asserted:
		//
		//   - no DB key signer wired in this environment: typed
		//     ErrSignerUnavailable (fail-fast before the nonce is
		//     consumed);
		//   - signer wired: the EK-bound SIGNED path must complete. The
		//     fixture provisions the DB key in the KMS and has the CA
		//     certify it, so the response must carry the CA's DB
		//     certificate for that key and a signature that verifies
		//     under it.
		//
		// An EK-binding rejection is NO LONGER legitimate here — the
		// prestage feature makes the gate pass by construction.
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		nonce := fetchNonce(t, ctx, cmd)
		digest := sha256.Sum256([]byte(uniqueID("provision-mp-sign")))
		resp, err := cmd.SignDigest(callCtx, &platformv1.SignDigestRequest{
			EkSerial:   fixture.ekSerial,
			MacAddress: fixture.macAddress,
			EkCert:     fixture.ekCertB64DER,
			EabKeyId:   fixture.eabKeyID,
			EabHmac:    fixture.eabHMAC,
			Nonce:      nonce,
			Digest:     digest[:],
		})
		if err == nil {
			assertDBSignature(t, fixture.dbKeyID, digest[:], resp.GetSignature(), resp.GetCertPem())
			t.Log("remote sign succeeded: CP DB key signed the digest through the EK-bound path")
			return
		}
		if !isSignerUnavailable(err) {
			t.Fatalf("EK-bound SignDigest must succeed or fail with the typed signer-unavailable, got: %v", err)
		}
		t.Log("SignDigest blocked by typed signer-unavailable: no CP DB key signer wired in this environment")
	})

	t.Run("SignDigestEKMismatch", func(t *testing.T) {
		// A mismatched presented EK certificate must never reach the
		// signer: either the fail-fast signer-unavailable fires first (no
		// signer wired at all), or the typed EK-binding rejection blocks
		// signing after authentication.
		callCtx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()

		_, mismatchB64DER := newSelfSignedEKCert(t)
		nonce := fetchNonce(t, ctx, cmd)
		digest := sha256.Sum256([]byte(uniqueID("provision-mp-sign-mismatch")))
		_, err := cmd.SignDigest(callCtx, &platformv1.SignDigestRequest{
			EkSerial:   fixture.ekSerial,
			MacAddress: fixture.macAddress,
			EkCert:     mismatchB64DER,
			EabKeyId:   fixture.eabKeyID,
			EabHmac:    fixture.eabHMAC,
			Nonce:      nonce,
			Digest:     digest[:],
		})
		if err == nil {
			t.Fatal("SignDigest with a mismatched EK certificate must never sign")
		}
		if !isSignerUnavailable(err) && !isEKBindingRejected(err) {
			t.Fatalf("expected signer-unavailable or typed EK-binding rejection, got: %v", err)
		}
	})
}
