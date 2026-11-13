package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// luksPCRRefusingBackend refuses every TPM enrollment the way the
// production PCR-checked TPM handler does: ErrLUKSPCRInvalid, wrapped.
type luksPCRRefusingBackend struct {
	luksWireBackend
}

func (b *luksPCRRefusingBackend) EnrollTPM(_ context.Context, req *LUKSEnrollTPMRequest) (*LUKSEnrollTPMResult, error) {
	return nil, fmt.Errorf("%w: pcrs %v", ErrLUKSPCRInvalid, req.PCRs)
}

// TestLUKSPCRInvalid_TransportMapping: an invalid PCR selection is invalid
// input on REST (400), gRPC and MCP (InvalidArgument) and QUIC
// (StatusInvalidArgument), not a server failure.
func TestLUKSPCRInvalid_TransportMapping(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", ErrLUKSPCRInvalid)

	if got := luksErrorToHTTP(err); got != http.StatusBadRequest {
		t.Errorf("REST: want 400, got %d", got)
	}
	if st, _ := status.FromError(luksErrorToGRPC(err)); st.Code() != codes.InvalidArgument {
		t.Errorf("gRPC: want InvalidArgument, got %v", st.Code())
	}
	if got := status.Code(ErrLUKSOperation{Cause: err}); got != codes.InvalidArgument {
		t.Errorf("MCP: want InvalidArgument, got %v", got)
	}
	if got := errResponseFrom(err).Status; got != quicwire.StatusInvalidArgument {
		t.Errorf("QUIC: want InvalidArgument, got %#x", got)
	}
}

// TestLUKSREST_EnrollTPMInvalidPCRs: a REST EnrollTPM with no PCR or with
// index 24 answers 400 naming the PCR error.
func TestLUKSREST_EnrollTPMInvalidPCRs(t *testing.T) {
	svc := NewLUKSService(logging.DefaultLogger(), &luksPCRRefusingBackend{}, rootYes())
	s := newTestRESTServerForPhase35(t)
	mustMountS6(t, s.SetLUKSService(svc, s6RESTGuard()))

	for name, pcrs := range map[string]string{"empty": `[]`, "index 24": `[7,24]`} {
		t.Run(name, func(t *testing.T) {
			body := `{"device":"/dev/sda","existing_passphrase":"` + luksTestExisting + `","pcrs":` + pcrs + `}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/luks/enroll/tpm", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+s6OperatorToken)
			rec := httptest.NewRecorder()
			s.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), ErrLUKSPCRInvalid.Error()) {
				t.Errorf("status=%d body=%s, want 400 with %q", rec.Code, rec.Body.String(), ErrLUKSPCRInvalid)
			}
		})
	}
}
