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
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// The secrets every LUKS REST case sends. No error string may carry them.
const (
	luksTestExisting = "existing-s3cret"
	luksTestNew      = "new-s3cret"
	luksTestOld      = "old-s3cret"
)

// luksWireBackend records each request the daemon hands it, so a test can
// prove a field crossed the wire, and answers with every reply field set, so a
// test can prove the client decoded it.
type luksWireBackend struct {
	mu         sync.Mutex
	devices    []string
	passphrase *LUKSEnrollPassphraseRequest
	fido2      *LUKSEnrollFIDO2Request
	tpm        *LUKSEnrollTPMRequest
	recovery   *LUKSEnrollRecoveryRequest
	remove     *LUKSRemoveKeyRequest
	unlock     *LUKSTestUnlockRequest
	change     *LUKSChangePassphraseRequest
}

func (b *luksWireBackend) record(set func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	set()
}

func (b *luksWireBackend) Status(_ context.Context, device string) (*LUKSStatus, error) {
	b.record(func() { b.devices = append(b.devices, device) })
	return &LUKSStatus{
		Device: device, IsLUKS: true, Version: 2, UUID: "uuid-1", Label: "root",
		Cipher: "aes-xts-plain64", ActiveSlots: []int32{0, 2},
	}, nil
}

func (b *luksWireBackend) ListSlots(_ context.Context, device string) (*LUKSListSlotsResult, error) {
	b.record(func() { b.devices = append(b.devices, device) })
	return &LUKSListSlotsResult{Device: device, Slots: []LUKSKeyslot{
		{Slot: 0, Type: LUKSKeyTypePassphrase, KeySize: 64, Priority: 1},
		{Slot: 2, Type: LUKSKeyTypeFIDO2, KeySize: 64, Priority: 2},
	}}, nil
}

func (b *luksWireBackend) Info(_ context.Context, device string) (*LUKSInfo, error) {
	b.record(func() { b.devices = append(b.devices, device) })
	return &LUKSInfo{
		Device: device, UUID: "uuid-1", Label: "root", Version: 2, Cipher: "aes-xts-plain64",
		KeySize: 512, SectorSize: 4096, Slots: []LUKSKeyslot{{Slot: 3, Type: LUKSKeyTypeTPM}},
		MetadataJSON: `{"tokens":{}}`,
	}, nil
}

func (b *luksWireBackend) EnrollPassphrase(_ context.Context, req *LUKSEnrollPassphraseRequest) (*LUKSEnrollPassphraseResult, error) {
	b.record(func() { b.passphrase = req })
	return &LUKSEnrollPassphraseResult{Slot: 1}, nil
}

func (b *luksWireBackend) EnrollFIDO2(_ context.Context, req *LUKSEnrollFIDO2Request) (*LUKSEnrollFIDO2Result, error) {
	b.record(func() { b.fido2 = req })
	return &LUKSEnrollFIDO2Result{Slot: 2, TokenID: "fido2-tok"}, nil
}

func (b *luksWireBackend) EnrollTPM(_ context.Context, req *LUKSEnrollTPMRequest) (*LUKSEnrollTPMResult, error) {
	b.record(func() { b.tpm = req })
	return &LUKSEnrollTPMResult{Slot: 3, TokenID: "tpm-tok"}, nil
}

func (b *luksWireBackend) EnrollRecovery(_ context.Context, req *LUKSEnrollRecoveryRequest) (*LUKSEnrollRecoveryResult, error) {
	b.record(func() { b.recovery = req })
	return &LUKSEnrollRecoveryResult{Slot: 4, RecoveryKey: "recovery-key-1"}, nil
}

func (b *luksWireBackend) RemoveKey(_ context.Context, req *LUKSRemoveKeyRequest) error {
	b.record(func() { b.remove = req })
	return nil
}

func (b *luksWireBackend) TestUnlock(_ context.Context, req *LUKSTestUnlockRequest) (bool, error) {
	b.record(func() { b.unlock = req })
	return true, nil
}

func (b *luksWireBackend) ChangePassphrase(_ context.Context, req *LUKSChangePassphraseRequest) error {
	b.record(func() { b.change = req })
	return nil
}

// newLUKSRESTSDKClient serves the daemon's real REST router, with svc as its
// LUKS service, and returns the SDK LUKS client over the SDK REST transport.
func newLUKSRESTSDKClient(t *testing.T, svc *LUKSService) *lukssdk.GRPCClient {
	t.Helper()
	s := newTestRESTServerForPhase35(t)
	s.SetLUKSService(svc)
	a := connectPhase35REST(t, s.router)
	return lukssdk.NewGRPCClientFromClient(platformv1.NewLUKSServiceClient(a.Connection()))
}

// isLUKSError reports whether err is, or wraps, the typed SDK error T.
func isLUKSError[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// luksRESTCase is one LUKS operation driven through the SDK client. call
// sends a request with every field set and device as its device; typed
// recognizes the operation's SDK error; check asserts the request reached the
// backend and the reply decoded.
type luksRESTCase struct {
	method   string
	mutating bool
	call     func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error)
	typed    func(error) bool
	check    func(t *testing.T, reply any, b *luksWireBackend)
}

func luksRESTCases() []luksRESTCase {
	return []luksRESTCase{
		{"Status", false,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.Status(ctx, &lukssdk.StatusRequest{Device: device})
			},
			isLUKSError[*lukssdk.ErrStatusFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				got := reply.(*lukssdk.StatusResponse)
				if got.Device != "/dev/sda" || !got.IsLUKS || got.Version != 2 || got.UUID != "uuid-1" ||
					got.Label != "root" || got.Cipher != "aes-xts-plain64" || !slices.Equal(got.ActiveSlots, []int32{0, 2}) {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"ListSlots", false,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.ListSlots(ctx, &lukssdk.ListSlotsRequest{Device: device})
			},
			isLUKSError[*lukssdk.ErrListSlotsFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				got := reply.(*lukssdk.ListSlotsResponse)
				want := []lukssdk.Keyslot{
					{Slot: 0, Type: lukssdk.KeyTypePassphrase, KeySize: 64, Priority: 1},
					{Slot: 2, Type: lukssdk.KeyTypeFIDO2, KeySize: 64, Priority: 2},
				}
				if got.Device != "/dev/sda" || !slices.Equal(got.Slots, want) {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"Info", false,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.Info(ctx, &lukssdk.InfoRequest{Device: device})
			},
			isLUKSError[*lukssdk.ErrInfoFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				got := reply.(*lukssdk.InfoResponse)
				if got.Device != "/dev/sda" || got.UUID != "uuid-1" || got.Label != "root" || got.Version != 2 ||
					got.Cipher != "aes-xts-plain64" || got.KeySize != 512 || got.SectorSize != 4096 ||
					got.MetadataJSON != `{"tokens":{}}` ||
					!slices.Equal(got.Slots, []lukssdk.Keyslot{{Slot: 3, Type: lukssdk.KeyTypeTPM}}) {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"EnrollPassphrase", true,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.EnrollPassphrase(ctx, &lukssdk.EnrollPassphraseRequest{
					Device: device, ExistingPassphrase: luksTestExisting, NewPassphrase: luksTestNew,
				})
			},
			isLUKSError[*lukssdk.ErrEnrollPassphraseFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				want := LUKSEnrollPassphraseRequest{Device: "/dev/sda", ExistingPassphrase: luksTestExisting, NewPassphrase: luksTestNew}
				if b.passphrase == nil || *b.passphrase != want {
					t.Errorf("backend got %+v", b.passphrase)
				}
				if got := reply.(*lukssdk.EnrollPassphraseResponse); got.Slot != 1 {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"EnrollFIDO2", true,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.EnrollFIDO2(ctx, &lukssdk.EnrollFIDO2Request{
					Device: device, ExistingPassphrase: luksTestExisting, CredentialID: "cred-1",
					RequirePIN: true, RequireUV: true,
				})
			},
			isLUKSError[*lukssdk.ErrEnrollFIDO2Failed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				want := LUKSEnrollFIDO2Request{
					Device: "/dev/sda", ExistingPassphrase: luksTestExisting, CredentialID: "cred-1",
					RequirePIN: true, RequireUV: true,
				}
				if b.fido2 == nil || *b.fido2 != want {
					t.Errorf("backend got %+v", b.fido2)
				}
				if got := reply.(*lukssdk.EnrollFIDO2Response); got.Slot != 2 || got.TokenID != "fido2-tok" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"EnrollTPM", true,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.EnrollTPM(ctx, &lukssdk.EnrollTPMRequest{
					Device: device, ExistingPassphrase: luksTestExisting, PCRs: []int32{0, 7},
				})
			},
			isLUKSError[*lukssdk.ErrEnrollTPMFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				if b.tpm == nil || b.tpm.Device != "/dev/sda" || b.tpm.ExistingPassphrase != luksTestExisting ||
					!slices.Equal(b.tpm.PCRs, []int32{0, 7}) {
					t.Errorf("backend got %+v", b.tpm)
				}
				if got := reply.(*lukssdk.EnrollTPMResponse); got.Slot != 3 || got.TokenID != "tpm-tok" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"EnrollRecovery", true,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.EnrollRecovery(ctx, &lukssdk.EnrollRecoveryRequest{Device: device, ExistingPassphrase: luksTestExisting})
			},
			isLUKSError[*lukssdk.ErrEnrollRecoveryFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				want := LUKSEnrollRecoveryRequest{Device: "/dev/sda", ExistingPassphrase: luksTestExisting}
				if b.recovery == nil || *b.recovery != want {
					t.Errorf("backend got %+v", b.recovery)
				}
				if got := reply.(*lukssdk.EnrollRecoveryResponse); got.Slot != 4 || got.RecoveryKey != "recovery-key-1" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"RemoveKey", true,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.RemoveKey(ctx, &lukssdk.RemoveKeyRequest{Device: device, Slot: 5})
			},
			isLUKSError[*lukssdk.ErrRemoveKeyFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				if b.remove == nil || *b.remove != (LUKSRemoveKeyRequest{Device: "/dev/sda", Slot: 5}) {
					t.Errorf("backend got %+v", b.remove)
				}
				if !reply.(*lukssdk.RemoveKeyResponse).Removed {
					t.Errorf("reply = %+v", reply)
				}
			}},
		{"TestUnlock", false,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.TestUnlock(ctx, &lukssdk.TestUnlockRequest{Device: device, Slot: 6})
			},
			isLUKSError[*lukssdk.ErrTestUnlockFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				if b.unlock == nil || *b.unlock != (LUKSTestUnlockRequest{Device: "/dev/sda", Slot: 6}) {
					t.Errorf("backend got %+v", b.unlock)
				}
				if !reply.(*lukssdk.TestUnlockResponse).Unlocked {
					t.Errorf("reply = %+v", reply)
				}
			}},
		{"ChangePassphrase", true,
			func(ctx context.Context, c *lukssdk.GRPCClient, device string) (any, error) {
				return c.ChangePassphrase(ctx, &lukssdk.ChangePassphraseRequest{
					Device: device, Slot: 7, OldPassphrase: luksTestOld, NewPassphrase: luksTestNew,
				})
			},
			isLUKSError[*lukssdk.ErrChangePassphraseFailed],
			func(t *testing.T, reply any, b *luksWireBackend) {
				want := LUKSChangePassphraseRequest{Device: "/dev/sda", Slot: 7, OldPassphrase: luksTestOld, NewPassphrase: luksTestNew}
				if b.change == nil || *b.change != want {
					t.Errorf("backend got %+v", b.change)
				}
				if !reply.(*lukssdk.ChangePassphraseResponse).Changed {
					t.Errorf("reply = %+v", reply)
				}
			}},
	}
}

// TestLUKSRESTClientAgainstDaemonRouter drives every LUKS operation of the SDK
// client over the SDK REST transport through the daemon's real router. A route
// the server does not register is a 404, a request key it does not decode
// leaves a backend field empty, and a reply key the client does not decode
// leaves a reply field empty, so each fails here.
func TestLUKSRESTClientAgainstDaemonRouter(t *testing.T) {
	cases := luksRESTCases()
	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		covered[tc.method] = true
	}
	for _, m := range platformv1.LUKSService_ServiceDesc.Methods {
		if !covered[m.MethodName] {
			t.Errorf("no REST case for LUKSService/%s", m.MethodName)
		}
	}

	backend := &luksWireBackend{}
	client := newLUKSRESTSDKClient(t, NewLUKSService(logging.DefaultLogger(), backend, rootYes()))
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			reply, err := tc.call(context.Background(), client, "/dev/sda")
			if err != nil {
				t.Fatalf("%s: %v", tc.method, err)
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			tc.check(t, reply, backend)
		})
	}

	// Status, ListSlots and Info name the device in the query string.
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !slices.Equal(backend.devices, []string{"/dev/sda", "/dev/sda", "/dev/sda"}) {
		t.Errorf("query devices = %q", backend.devices)
	}
}

// TestLUKSRESTClientAgainstDaemonRouter_ErrorsSurface proves a daemon refusal
// reaches the SDK caller as the operation's typed error, wrapping the gRPC
// code and bare message QUIC and MCP return, and that no error string carries
// a passphrase the request sent.
func TestLUKSRESTClientAgainstDaemonRouter_ErrorsSurface(t *testing.T) {
	refusals := []struct {
		name     string
		backend  LUKSBackend
		root     RootChecker
		device   string
		mutating bool // the refusal applies only to mutating operations
		wantCode codes.Code
		wantErr  error
	}{
		{"device required", &luksWireBackend{}, rootYes(), "", false, codes.InvalidArgument, ErrLUKSDeviceRequired},
		{"not configured", nil, rootYes(), "/dev/sda", false, codes.Unavailable, ErrLUKSNotConfigured},
		{"root required", &luksWireBackend{}, rootFalse(), "/dev/sda", true, codes.PermissionDenied, ErrLUKSRootRequired},
	}
	for _, refusal := range refusals {
		client := newLUKSRESTSDKClient(t, NewLUKSService(logging.DefaultLogger(), refusal.backend, refusal.root))
		for _, tc := range luksRESTCases() {
			if refusal.mutating && !tc.mutating {
				continue
			}
			t.Run(refusal.name+"/"+tc.method, func(t *testing.T) {
				_, err := tc.call(context.Background(), client, refusal.device)
				if !tc.typed(err) {
					t.Fatalf("err = %v (%T), want the %s typed error", err, err, tc.method)
				}
				st, ok := status.FromError(errors.Unwrap(err))
				if !ok || st.Code() != refusal.wantCode || st.Message() != refusal.wantErr.Error() {
					t.Errorf("cause = %v, want %s %q", errors.Unwrap(err), refusal.wantCode, refusal.wantErr)
				}
				for _, secret := range []string{luksTestExisting, luksTestNew, luksTestOld} {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("error %q carries a passphrase", err)
					}
				}
			})
		}
	}
}

// TestLUKSREST_MalformedBodyHidesInput proves a body that does not decode is a
// 400 with a fixed message: the JSON decoder's error quotes the input, and the
// input holds a passphrase.
func TestLUKSREST_MalformedBodyHidesInput(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetLUKSService(NewLUKSService(logging.DefaultLogger(), &luksWireBackend{}, rootYes()))

	bodies := map[string]string{
		"truncated":    `{"device":"/dev/sda","new_passphrase":"` + luksTestNew,
		"invalid char": `{"device":"/dev/sda","new_passphrase":"` + luksTestNew + `"x}`,
		"wrong type":   `{"device":"/dev/sda","existing_passphrase":["` + luksTestExisting + `"]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/luks/enroll/passphrase", strings.NewReader(body))
			rec := httptest.NewRecorder()
			s.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			got := rec.Body.String()
			if !strings.Contains(got, ErrLUKSMalformedBody.Error()) {
				t.Errorf("body = %s, want %q", got, ErrLUKSMalformedBody)
			}
			if strings.Contains(got, luksTestNew) || strings.Contains(got, luksTestExisting) {
				t.Errorf("body %s carries a passphrase", got)
			}
		})
	}
}
