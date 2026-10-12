package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// importUnsupportedBackend is a PIVBackend whose Import fails closed like the
// production backend.
type importUnsupportedBackend struct {
	fakePIVBackend
}

func (importUnsupportedBackend) Import(context.Context, *PIVImportRequest) error {
	return ErrPIVKeyImportUnsupported
}

func TestPIVService_Import_PropagatesUnsupported(t *testing.T) {
	svc := NewPIVService(logging.DefaultLogger(), &importUnsupportedBackend{})
	err := svc.Import(context.Background(), &PIVImportRequest{Slot: "9a", PrivateKeyPEM: "pem"}) //nolint:staticcheck // SA1019: plain field is the simplest valid request.
	if !errors.Is(err, ErrPIVKeyImportUnsupported) {
		t.Fatalf("want ErrPIVKeyImportUnsupported, got %v", err)
	}
}

// TestPIVKeyImportUnsupported_TransportMapping proves every transport reports
// the unsupported error as "not implemented", including when wrapped.
func TestPIVKeyImportUnsupported_TransportMapping(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", ErrPIVKeyImportUnsupported)

	if got := pivErrorToHTTP(err); got != http.StatusNotImplemented {
		t.Errorf("REST: want %d, got %d", http.StatusNotImplemented, got)
	}
	if st, _ := status.FromError(pivErrorToGRPC(err)); st.Code() != codes.Unimplemented {
		t.Errorf("gRPC: want Unimplemented, got %v", st.Code())
	}
	if got := errResponseFrom(err).Status; got != quicwire.StatusNotImplemented {
		t.Errorf("QUIC: want StatusNotImplemented, got %#x", got)
	}
}

// Unrelated errors must keep their existing mappings.
func TestPIVKeyImportUnsupported_DoesNotCaptureOtherErrors(t *testing.T) {
	if got := pivErrorToHTTP(ErrPIVNotConfigured); got != http.StatusServiceUnavailable {
		t.Errorf("REST: want 503, got %d", got)
	}
}
