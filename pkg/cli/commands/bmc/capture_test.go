package bmc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tlsBMC starts a loopback TLS listener standing in for the BMC's HTTPS port
// and returns its host, port and the SPKI pin of the certificate it presents.
func tlsBMC(t *testing.T) (host string, port int, pin string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	port, err = strconv.Atoi(portStr)
	require.NoError(t, err)
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	return host, port, hex.EncodeToString(sum[:])
}

func TestCaptureAndConfirmSPKI_Accepted(t *testing.T) {
	for _, answer := range []string{"yes\n", "Y\n", "  yes  \n"} {
		t.Run(answer, func(t *testing.T) {
			host, port, wantPin := tlsBMC(t)
			withStdin(t, answer)

			var pin string
			stderr, err := captureStderr(t, func() error {
				var captureErr error
				pin, captureErr = captureAndConfirmSPKI(context.Background(), host, port)
				return captureErr
			})

			require.NoError(t, err)
			assert.Equal(t, wantPin, pin)
			assert.Contains(t, stderr, "BMC TLS certificate at "+net.JoinHostPort(host, strconv.Itoa(port)))
			assert.Contains(t, stderr, "SPKI pin:   "+wantPin)
			assert.Contains(t, stderr, "Do you trust this certificate? [yes/no]")
			assert.Contains(t, stderr, "pass: --bmc-pin "+wantPin)
		})
	}
}

func TestCaptureAndConfirmSPKI_Rejected(t *testing.T) {
	for name, answer := range map[string]string{"no": "no\n", "other": "sure\n", "EOF": ""} {
		t.Run(name, func(t *testing.T) {
			host, port, wantPin := tlsBMC(t)
			withStdin(t, answer)

			var pin string
			stderr, err := captureStderr(t, func() error {
				var captureErr error
				pin, captureErr = captureAndConfirmSPKI(context.Background(), host, port)
				return captureErr
			})

			require.ErrorIs(t, err, ErrBMCNoPinOrCAFile{})
			assert.Empty(t, pin)
			assert.Contains(t, stderr, "SPKI pin:   "+wantPin, "the pin is shown before the operator decides")
			assert.NotContains(t, stderr, "Accepted.")
		})
	}
}

func TestCaptureAndConfirmSPKI_DialFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().(*net.TCPAddr)
	require.NoError(t, ln.Close())

	_, err = captureAndConfirmSPKI(context.Background(), "127.0.0.1", addr.Port)

	var dialErr ErrBMCCaptureDial
	require.ErrorAs(t, err, &dialErr)
	assert.Equal(t, addr.String(), dialErr.Host)
	require.Error(t, dialErr.Unwrap())
	assert.Contains(t, err.Error(), "bmc: TLS capture dial to "+addr.String()+" failed: ")
}

func TestCaptureAndConfirmSPKI_HonoursCancelledContext(t *testing.T) {
	host, port, _ := tlsBMC(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := captureAndConfirmSPKI(ctx, host, port)

	var dialErr ErrBMCCaptureDial
	require.ErrorAs(t, err, &dialErr)
	require.ErrorIs(t, err, context.Canceled)
}

func TestCaptureAndConfirmSPKI_PeerNotTLS(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().(*net.TCPAddr)

	_, err := captureAndConfirmSPKI(context.Background(), "127.0.0.1", addr.Port)

	var dialErr ErrBMCCaptureDial
	require.ErrorAs(t, err, &dialErr, "a plain-HTTP port fails the capture handshake")
}
