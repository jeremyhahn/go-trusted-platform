package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// A FIDO2 enrolment that asks for a PIN is refused (#934): the SDK has no
// PIN-capable fido2 handler, so the slot would be guarded by presence alone.

func TestLUKSService_EnrollFIDO2_RequirePINRefusedBeforeBackend(t *testing.T) {
	// A non-root daemon still answers with the PIN refusal: the caller learns
	// the request can never succeed, not that it should retry as root.
	for name, root := range map[string]RootChecker{"root": rootYes(), "not root": rootFalse()} {
		t.Run(name, func(t *testing.T) {
			backend := &luksWireBackend{}
			svc := NewLUKSService(logging.DefaultLogger(), backend, root)
			_, err := svc.EnrollFIDO2(context.Background(), &LUKSEnrollFIDO2Request{
				Device: "/dev/sda", ExistingPassphrase: luksTestExisting, CredentialID: "cred-1",
				RequirePIN: true, RequireUV: true,
			})
			if !errors.Is(err, ErrLUKSFIDO2PINUnsupported) {
				t.Fatalf("err = %v, want ErrLUKSFIDO2PINUnsupported", err)
			}
			if backend.fido2 != nil {
				t.Errorf("backend reached with %+v", backend.fido2)
			}
		})
	}
}

func TestLUKSService_EnrollFIDO2_RequireUVReachesBackend(t *testing.T) {
	backend := &luksWireBackend{}
	svc := NewLUKSService(logging.DefaultLogger(), backend, rootYes())
	res, err := svc.EnrollFIDO2(context.Background(), &LUKSEnrollFIDO2Request{
		Device: "/dev/sda", ExistingPassphrase: luksTestExisting, CredentialID: "cred-1", RequireUV: true,
	})
	if err != nil {
		t.Fatalf("EnrollFIDO2: %v", err)
	}
	if res.Slot != 2 || backend.fido2 == nil || !backend.fido2.RequireUV {
		t.Errorf("result %+v, backend got %+v", res, backend.fido2)
	}
}

// TestLUKSFIDO2PINUnsupported_TransportMapping proves every transport reports
// the refusal as an invalid request carrying the message, including when
// wrapped. Unix serves the gRPC service, and MCP answers through
// ErrLUKSOperation, so both follow the gRPC mapping.
func TestLUKSFIDO2PINUnsupported_TransportMapping(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", ErrLUKSFIDO2PINUnsupported)

	if got := luksErrorToHTTP(err); got != http.StatusBadRequest {
		t.Errorf("REST: want 400, got %d", got)
	}
	if st, _ := status.FromError(luksErrorToGRPC(err)); st.Code() != codes.InvalidArgument {
		t.Errorf("gRPC: want InvalidArgument, got %v", st.Code())
	}
	if got := status.Code(ErrLUKSOperation{Cause: err}); got != codes.InvalidArgument {
		t.Errorf("MCP: want InvalidArgument, got %v", got)
	}
	resp := errResponseFrom(err)
	if resp.Status != quicwire.StatusInvalidArgument || !strings.Contains(string(resp.Payload), "#584") {
		t.Errorf("QUIC: status=%#x payload=%q, want InvalidArgument naming the SDK seam", resp.Status, resp.Payload)
	}
}

// An unrelated cause keeps its own mapping.
func TestLUKSFIDO2PINUnsupported_DoesNotCaptureOtherErrors(t *testing.T) {
	if got := luksErrorToHTTP(ErrLUKSNotConfigured); got != http.StatusServiceUnavailable {
		t.Errorf("REST: want 503, got %d", got)
	}
	if got := errResponseFrom(ErrLUKSRootRequired).Status; got == quicwire.StatusInvalidArgument {
		t.Errorf("QUIC: root required mapped to InvalidArgument")
	}
}

func TestLUKSREST_EnrollFIDO2RequirePINRefused(t *testing.T) {
	backend := &luksWireBackend{}
	svc := NewLUKSService(logging.DefaultLogger(), backend, rootYes())

	t.Run("SDK client", func(t *testing.T) {
		client := newLUKSRESTSDKClient(t, svc)
		_, err := client.EnrollFIDO2(context.Background(), &lukssdk.EnrollFIDO2Request{
			Device: "/dev/sda", ExistingPassphrase: luksTestExisting, CredentialID: "cred-1", RequirePIN: true,
		})
		if !isLUKSError[*lukssdk.ErrEnrollFIDO2Failed](err) {
			t.Fatalf("err = %v (%T), want *ErrEnrollFIDO2Failed", err, err)
		}
		st, ok := status.FromError(errors.Unwrap(err))
		if !ok || st.Code() != codes.InvalidArgument || st.Message() != ErrLUKSFIDO2PINUnsupported.Error() {
			t.Errorf("cause = %v, want InvalidArgument %q", errors.Unwrap(err), ErrLUKSFIDO2PINUnsupported)
		}
		if strings.Contains(err.Error(), luksTestExisting) {
			t.Errorf("error %q carries the passphrase", err)
		}
	})

	t.Run("HTTP", func(t *testing.T) {
		s := newTestRESTServerForPhase35(t)
		mustMountS6(t, s.SetLUKSService(svc, s6RESTGuard()))
		body := `{"device":"/dev/sda","existing_passphrase":"` + luksTestExisting + `","credential_id":"cred-1","require_pin":true}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/luks/enroll/fido2", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+s6OperatorToken)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), ErrLUKSFIDO2PINUnsupported.Error()) {
			t.Errorf("status=%d body=%s, want 400 with %q", rec.Code, rec.Body.String(), ErrLUKSFIDO2PINUnsupported)
		}
	})

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.fido2 != nil {
		t.Errorf("backend reached with %+v", backend.fido2)
	}
}

// TestLUKSGRPCAndMCP_EnrollFIDO2RequirePINRefused drives the gRPC service (the
// one the Unix socket serves) and the MCP tool with the same request.
func TestLUKSGRPCAndMCP_EnrollFIDO2RequirePINRefused(t *testing.T) {
	backend := &luksWireBackend{}
	provider, grpcSvc := luksTwins(backend, true)

	_, err := grpcSvc.EnrollFIDO2(context.Background(), &platformv1.LUKSEnrollFIDO2Request{
		Device: "/dev/x", ExistingPassphrase: "e", CredentialId: "c", RequirePin: true,
	})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || st.Message() != ErrLUKSFIDO2PINUnsupported.Error() {
		t.Errorf("gRPC: err = %v, want InvalidArgument %q", err, ErrLUKSFIDO2PINUnsupported)
	}

	_, err = provider.LUKSEnrollFIDO2(context.Background(), map[string]interface{}{
		"device": "/dev/x", "existing_passphrase": "e", "credential_id": "c", "require_pin": true,
	})
	if !errors.Is(err, ErrLUKSFIDO2PINUnsupported) || status.Code(err) != codes.InvalidArgument {
		t.Errorf("MCP: err = %v (code %v), want ErrLUKSFIDO2PINUnsupported as InvalidArgument", err, status.Code(err))
	}

	if backend.fido2 != nil {
		t.Errorf("backend reached with %+v", backend.fido2)
	}
}

func TestSDKEmbedded_EnrollFIDO2RequirePINRefused(t *testing.T) {
	backend := &luksWireBackend{}
	conn := connectLUKSEmbedded(t, newLUKSServicer(backend, rootYes()))
	err := conn.Invoke(context.Background(), platformv1.LUKSService_EnrollFIDO2_FullMethodName,
		&platformv1.LUKSEnrollFIDO2Request{Device: "/dev/sda", ExistingPassphrase: "e", CredentialId: "c", RequirePin: true},
		&platformv1.LUKSEnrollFIDO2Response{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || st.Message() != ErrLUKSFIDO2PINUnsupported.Error() {
		t.Errorf("embedded: err = %v, want InvalidArgument %q", err, ErrLUKSFIDO2PINUnsupported)
	}
	if backend.fido2 != nil {
		t.Errorf("backend reached with %+v", backend.fido2)
	}
}

func TestLUKSQUIC_EnrollFIDO2RequirePINRefused(t *testing.T) {
	backend := &luksWireBackend{}
	h := &luksQUICHandlers{service: NewLUKSService(logging.DefaultLogger(), backend, rootYes())}
	payload, err := quicwire.EncodePayload(&quicwire.LUKSEnrollFIDO2Req{
		Device: "/dev/sda", ExistingPassphrase: luksTestExisting, CredentialID: "c", RequirePIN: true,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	resp := h.enrollFIDO2(context.Background(), payload)
	if resp.Status != quicwire.StatusInvalidArgument || string(resp.Payload) != ErrLUKSFIDO2PINUnsupported.Error() {
		t.Errorf("status=%#x payload=%q, want InvalidArgument %q", resp.Status, resp.Payload, ErrLUKSFIDO2PINUnsupported)
	}
	if backend.fido2 != nil {
		t.Errorf("backend reached with %+v", backend.fido2)
	}
}
