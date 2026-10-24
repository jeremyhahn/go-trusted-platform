package bmc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

func peerState(leaves ...string) tls.ConnectionState {
	state := tls.ConnectionState{}
	for _, raw := range leaves {
		state.PeerCertificates = append(state.PeerCertificates, &x509.Certificate{Raw: []byte(raw)})
	}
	return state
}

func pinnedConfig(inner func(tls.ConnectionState) error) *tls.Config {
	cfg := &tls.Config{VerifyConnection: inner}
	withPinnedPeer()(cfg)
	return cfg
}

func TestWithPinnedPeer_PinsFirstLeaf(t *testing.T) {
	cfg := pinnedConfig(nil)

	if err := cfg.VerifyConnection(peerState("leaf-a", "issuer")); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	// A resumed or repeated connection to the same endpoint must pass.
	if err := cfg.VerifyConnection(peerState("leaf-a")); err != nil {
		t.Fatalf("same leaf again: %v", err)
	}
}

func TestWithPinnedPeer_RejectsMismatch(t *testing.T) {
	tests := []struct {
		name  string
		first tls.ConnectionState
		later tls.ConnectionState
	}{
		{"different leaf after pin", peerState("leaf-a"), peerState("leaf-b")},
		{"no peer certificate", peerState("leaf-a"), peerState()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := pinnedConfig(nil)
			if err := cfg.VerifyConnection(tt.first); err != nil {
				t.Fatalf("first connection: %v", err)
			}
			err := cfg.VerifyConnection(tt.later)
			var mismatch ErrPeerPinMismatch
			if !errors.As(err, &mismatch) {
				t.Fatalf("error = %v, want ErrPeerPinMismatch", err)
			}
			if !strings.Contains(err.Error(), "different certificate") {
				t.Fatalf("message = %q, want it to name the certificate change", err.Error())
			}
		})
	}
}

func TestWithPinnedPeer_InnerVerifyRunsFirst(t *testing.T) {
	rejected := errors.New("chain does not verify")
	calls := 0
	cfg := pinnedConfig(func(state tls.ConnectionState) error {
		calls++
		if string(state.PeerCertificates[0].Raw) == "untrusted" {
			return rejected
		}
		return nil
	})

	if err := cfg.VerifyConnection(peerState("untrusted")); !errors.Is(err, rejected) {
		t.Fatalf("error = %v, want the wrapped verifier's error", err)
	}
	// The rejected leaf must not have been pinned: a trusted leaf is
	// still accepted as the first pin.
	if err := cfg.VerifyConnection(peerState("trusted")); err != nil {
		t.Fatalf("trusted leaf after a rejected one: %v", err)
	}
	if calls != 2 {
		t.Fatalf("inner verifier calls = %d, want 2", calls)
	}
}

func errorResponse(status int, body io.Reader) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(body),
	}
}

func TestParseRedfishError_Messages(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "extended info appended with resolution",
			body: `{"error":{"message":"A general error has occurred.","@Message.ExtendedInfo":[` +
				`{"MessageId":"Base.1.4.PropertyValueNotInList","Message":"Image is not valid.","Resolution":"Use an ISO URL."},` +
				`{"MessageId":"Base.1.4.Empty","Message":""},` +
				`{"MessageId":"Base.1.4.Busy","Message":"Retry later."}]}}`,
			want: "A general error has occurred. [Base.1.4.PropertyValueNotInList: Image is not valid. " +
				"(Resolution: Use an ISO URL.)] [Base.1.4.Busy: Retry later.]",
		},
		{
			name: "plain body kept verbatim",
			body: "upstream gateway timeout",
			want: "upstream gateway timeout",
		},
		{
			name: "JSON without an error message kept verbatim",
			body: `{"error":{}}`,
			want: `{"error":{}}`,
		},
		{
			name: "empty body falls back to the status",
			body: "",
			want: http.StatusText(http.StatusBadRequest),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseRedfishError(errorResponse(http.StatusBadRequest, strings.NewReader(tt.body)), http.MethodPost, "/redfish/v1/x")
			var reqErr ErrRedfishRequest
			if !errors.As(err, &reqErr) {
				t.Fatalf("error = %v, want ErrRedfishRequest", err)
			}
			if reqErr.Message != tt.want {
				t.Errorf("message = %q, want %q", reqErr.Message, tt.want)
			}
			if reqErr.StatusCode != http.StatusBadRequest || reqErr.Method != http.MethodPost || reqErr.Path != "/redfish/v1/x" {
				t.Errorf("request fields = %+v, want POST /redfish/v1/x 400", reqErr)
			}
		})
	}
}

func TestParseRedfishError_UnreadableBody(t *testing.T) {
	body := iotest.ErrReader(errors.New("connection reset"))
	err := parseRedfishError(errorResponse(http.StatusInternalServerError, body), http.MethodGet, "/redfish/v1/")
	var reqErr ErrRedfishRequest
	if !errors.As(err, &reqErr) {
		t.Fatalf("error = %v, want ErrRedfishRequest", err)
	}
	if reqErr.StatusCode != http.StatusInternalServerError || reqErr.Message != http.StatusText(http.StatusInternalServerError) {
		t.Fatalf("error = %+v, want the status line when the body cannot be read", reqErr)
	}
}
