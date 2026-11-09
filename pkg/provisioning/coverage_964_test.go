package provisioning

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestWrappedError_MessageAndUnwrap(t *testing.T) {
	cause := ErrTimeout
	err := &WrappedError{Msg: "boot delivery", Err: cause}

	assert.Equal(t, "boot delivery: "+cause.Error(), err.Error())
	assert.ErrorIs(t, err, ErrTimeout)
	assert.False(t, errors.Is(err, ErrServerError))
}

func TestOrDefaultTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "zero falls back to the default", timeout: 0, want: 30 * time.Second},
		{name: "explicit timeout is kept", timeout: 5 * time.Second, want: 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, orDefaultTimeout(tt.timeout))
		})
	}
}

// newClientForURL builds an mTLS client against serverURL with a fresh device
// certificate and the given CA pool's server.
func newClientForURL(t *testing.T, serverURL string) *Client {
	t.Helper()

	_, caPool := startTLSTestServer(t, http.NotFoundHandler())
	cert, key := generateTestCertificate(t, "test-device")
	client, err := NewClient(&ClientConfig{
		ServerURL:   serverURL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}, logging.DefaultLogger())
	require.NoError(t, err)
	return client
}

// closedServerURL returns the URL of a TLS server that is no longer listening.
func closedServerURL(t *testing.T) string {
	t.Helper()

	server, _ := startTLSTestServer(t, http.NotFoundHandler())
	url := server.URL
	server.Close()
	return url
}

func TestClient_RequestErrors(t *testing.T) {
	tests := []struct {
		name      string
		serverURL func(t *testing.T) string
		call      func(c *Client) (any, error)
		want      error
	}{
		{
			name:      "activate with an unparseable URL",
			serverURL: func(*testing.T) string { return "https://bad\x7fhost" },
			call:      func(c *Client) (any, error) { return c.Activate(context.Background()) },
			want:      ErrActivationFailed,
		},
		{
			name:      "heartbeat with an unparseable URL",
			serverURL: func(*testing.T) string { return "https://bad\x7fhost" },
			call:      func(c *Client) (any, error) { return c.Heartbeat(context.Background()) },
			want:      ErrHeartbeatFailed,
		},
		{
			name:      "activate against a closed server",
			serverURL: closedServerURL,
			call:      func(c *Client) (any, error) { return c.Activate(context.Background()) },
			want:      ErrConnectionFailed,
		},
		{
			name:      "heartbeat against a closed server",
			serverURL: closedServerURL,
			call:      func(c *Client) (any, error) { return c.Heartbeat(context.Background()) },
			want:      ErrConnectionFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newClientForURL(t, tt.serverURL(t))

			resp, err := tt.call(client)

			require.ErrorIs(t, err, tt.want)
			var sentinelErr *SentinelCauseError
			require.ErrorAs(t, err, &sentinelErr)
			assert.Equal(t, tt.want, sentinelErr.Sentinel)
			assert.Nil(t, resp)
		})
	}
}
