package rest

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// handlerTransport serves each request with an in-memory handler: no
// listener, no port.
type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, r)
	return recorder.Result(), nil
}

func TestNewWithRoundTripper_SendsThroughTheRoundTripper(t *testing.T) {
	var gotPath, gotAuth string
	rt := handlerTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})}

	a, err := NewWithRoundTripper("https://daemon.invalid/", rt, "tok")
	require.NoError(t, err)

	err = a.Connection().Invoke(context.Background(), "/platform.v1.PlatformIAMService/ListUsers",
		&platformv1.ListIAMUsersRequest{TenantId: "acme"}, &platformv1.ListIAMUsersResponse{})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/iam/tenants/acme/users", gotPath)
	assert.Equal(t, "Bearer tok", gotAuth)
}

func TestNewWithRoundTripper_RefusesMissingInputs(t *testing.T) {
	rt := handlerTransport{handler: http.NotFoundHandler()}

	_, err := NewWithRoundTripper("", rt, "")
	assert.ErrorIs(t, err, platform.ErrEmptyAddress)

	_, err = NewWithRoundTripper("https://daemon.invalid", nil, "")
	var nilRT ErrNilRoundTripper
	assert.True(t, errors.As(err, &nilRT), "got %v", err)
}

// TestNewWithRoundTripper_RefusesPlaintext shows that the in-process
// constructor refuses a plain http base URL the same way Connect does: the
// adapter attaches the bearer token to every request, so a plaintext base URL
// over a network RoundTripper would send the credential in the clear.
func TestNewWithRoundTripper_RefusesPlaintext(t *testing.T) {
	rt := handlerTransport{handler: http.NotFoundHandler()}

	for _, token := range []string{"tok", ""} {
		a, err := NewWithRoundTripper("http://daemon.invalid", rt, token)
		var insecure platform.ErrInsecureTransport
		assert.True(t, errors.As(err, &insecure), "token %q: got %v, want ErrInsecureTransport", token, err)
		assert.Nil(t, a, "token %q", token)
	}

	_, err := NewWithRoundTripper("daemon.invalid", rt, "tok")
	var insecure platform.ErrInsecureTransport
	assert.True(t, errors.As(err, &insecure), "a base URL without a scheme: got %v, want ErrInsecureTransport", err)
}

// errBindRefused is the error a BindFunc returns when it cannot complete
// the request with the binding it was handed.
type errBindRefused struct{}

func (errBindRefused) Error() string { return "the bind function refused the binding" }

// otherLabelExport derives a binding under a label the daemon does not
// check, so the proof it yields does not match the connection's binding.
func otherLabelExport(state *tls.ConnectionState) ([]byte, error) {
	return state.ExportKeyingMaterial("EXPORTER-not-the-platform-label", nil, transport.ChannelBindingSize)
}

// TestInvoke_ChannelBinding drives a bound call end to end: the BindFunc
// writes the binding into the request's tenant, so the route the request
// travels carries the proof, and the daemon compares it with the exporter
// of the connection the request arrived on.
func TestInvoke_ChannelBinding(t *testing.T) {
	const iamPrefix = "/api/v1/iam/tenants/"
	var iamRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasPrefix(r.URL.Path, iamPrefix) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
			return
		}
		iamRequests.Add(1)
		want, err := transport.ExportChannelBinding(r.TLS)
		proof := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, iamPrefix), "/users")
		if err != nil || proof != hex.EncodeToString(want) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"error":"channel binding mismatch"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{"users":[{"id":"u1"}]}}`))
	}))
	defer server.Close()

	// overTLS connects to the daemon over a real TLS 1.3 connection, the
	// only kind a bound call can dial.
	overTLS := func(t *testing.T) *Adapter {
		t.Helper()
		connected, err := Connect(context.Background(), platform.NewOptions(
			platform.WithRESTAddr(server.URL),
			trustServer(server),
			platform.WithTimeout(time.Minute),
		))
		require.NoError(t, err)
		adapter := connected.(*Adapter)
		t.Cleanup(func() {
			if err := adapter.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		})
		return adapter
	}

	tests := []struct {
		name         string
		adapter      func(t *testing.T) *Adapter
		option       func(req *platformv1.ListIAMUsersRequest) grpc.CallOption
		wantRequests int32
		check        func(t *testing.T, err error, reply *platformv1.ListIAMUsersResponse)
	}{
		{
			name:    "the request carries the binding of the connection it travels on",
			adapter: overTLS,
			option: func(req *platformv1.ListIAMUsersRequest) grpc.CallOption {
				return transport.WithChannelBinding(func(_ context.Context, binding []byte) error {
					req.TenantId = hex.EncodeToString(binding)
					return nil
				})
			},
			wantRequests: 1,
			check: func(t *testing.T, err error, reply *platformv1.ListIAMUsersResponse) {
				require.NoError(t, err)
				require.Len(t, reply.GetUsers(), 1)
				assert.Equal(t, "u1", reply.GetUsers()[0].GetId())
			},
		},
		{
			name:    "a binding that does not match the connection is refused by the daemon",
			adapter: overTLS,
			option: func(req *platformv1.ListIAMUsersRequest) grpc.CallOption {
				return transport.WithExportedChannelBinding(otherLabelExport, func(_ context.Context, binding []byte) error {
					req.TenantId = hex.EncodeToString(binding)
					return nil
				})
			},
			wantRequests: 1,
			check: func(t *testing.T, err error, _ *platformv1.ListIAMUsersResponse) {
				assert.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
			},
		},
		{
			name:    "a connection that exports no binding stops the call before a request",
			adapter: overTLS,
			option: func(*platformv1.ListIAMUsersRequest) grpc.CallOption {
				return transport.WithExportedChannelBinding(
					func(*tls.ConnectionState) ([]byte, error) {
						return nil, &transport.ErrChannelUnbound{Reason: "the exporter produced no keying material"}
					},
					func(context.Context, []byte) error { return nil },
				)
			},
			check: func(t *testing.T, err error, _ *platformv1.ListIAMUsersResponse) {
				var unavailable *transport.ErrChannelBindingUnavailable
				assert.True(t, errors.As(err, &unavailable), "err = %v, want ErrChannelBindingUnavailable", err)
				var unbound *transport.ErrChannelUnbound
				assert.True(t, errors.As(err, &unbound), "err = %v, want it to wrap ErrChannelUnbound", err)
			},
		},
		{
			name:    "a BindFunc that refuses the binding stops the call before a request",
			adapter: overTLS,
			option: func(*platformv1.ListIAMUsersRequest) grpc.CallOption {
				return transport.WithChannelBinding(func(context.Context, []byte) error { return errBindRefused{} })
			},
			check: func(t *testing.T, err error, _ *platformv1.ListIAMUsersResponse) {
				assert.True(t, errors.As(err, new(errBindRefused)), "err = %v, want errBindRefused", err)
			},
		},
		{
			name: "an adapter over a caller's RoundTripper has no TLS connection to bind to, even over https",
			adapter: func(t *testing.T) *Adapter {
				a, err := NewWithRoundTripper("https://daemon.invalid", handlerTransport{handler: server.Config.Handler}, "")
				require.NoError(t, err)
				return a
			},
			option: func(*platformv1.ListIAMUsersRequest) grpc.CallOption {
				return transport.WithChannelBinding(func(context.Context, []byte) error { return nil })
			},
			check: func(t *testing.T, err error, _ *platformv1.ListIAMUsersResponse) {
				var unavailable *transport.ErrChannelBindingUnavailable
				assert.True(t, errors.As(err, &unavailable), "err = %v, want ErrChannelBindingUnavailable", err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := tt.adapter(t)
			before := iamRequests.Load()
			req := &platformv1.ListIAMUsersRequest{TenantId: "unbound"}
			reply := &platformv1.ListIAMUsersResponse{}

			err := adapter.Connection().Invoke(context.Background(),
				"/platform.v1.PlatformIAMService/ListUsers", req, reply, tt.option(req))

			tt.check(t, err, reply)
			assert.Equal(t, tt.wantRequests, iamRequests.Load()-before, "IAM requests that reached the daemon")
		})
	}
}
