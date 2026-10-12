// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// stalledCallWatchdog is how long a test waits for a bound call against a
// stalled server before failing: far beyond any bound the tests set, so
// only a call that ignores its bound reaches it.
const stalledCallWatchdog = 10 * time.Second

// stallingListener accepts TCP connections and never answers the TLS
// handshake on them, like a daemon that hangs after accept. It returns the
// listener's https URL.
func stallingListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
		done  = make(chan struct{})
	)
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			if err := conn.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}
	})
	return "https://" + listener.Addr().String()
}

// bindAgainst runs bindChannel on adapter in a goroutine and returns its
// error, failing the test if the call outlives stalledCallWatchdog.
func bindAgainst(t *testing.T, ctx context.Context, adapter *Adapter) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		bound, err := adapter.bindChannel(ctx, func(context.Context, []byte) error { return nil })
		if err == nil {
			err = bound.release()
		}
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(stalledCallWatchdog):
		t.Fatal("the bound call did not return: the dial and handshake are unbounded")
		return nil
	}
}

func TestBindChannel_BindsTheDialedConnection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	connected, err := Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
		platform.WithTimeout(time.Minute),
	))
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	adapter := connected.(*Adapter)
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	var binding []byte
	bound, err := adapter.bindChannel(context.Background(), func(_ context.Context, b []byte) error {
		binding = b
		return nil
	})
	if err != nil {
		t.Fatalf("bindChannel() returned error: %v", err)
	}
	if len(binding) != transport.ChannelBindingSize {
		t.Errorf("binding is %d bytes, want %d", len(binding), transport.ChannelBindingSize)
	}
	if err := bound.release(); err != nil {
		t.Errorf("release() returned error: %v", err)
	}
}

// TestBindChannel_StalledHandshake verifies a server that accepts TCP and
// never answers TLS cannot hold a bound call: the adapter's timeout bounds
// the dial and handshake when the context has no deadline, and an earlier
// context deadline still ends the call first.
func TestBindChannel_StalledHandshake(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		ctx     func() (context.Context, context.CancelFunc)
	}{
		{
			name:    "a context without a deadline takes the adapter's timeout",
			timeout: 200 * time.Millisecond,
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
		{
			name:    "an earlier context deadline wins over the adapter's timeout",
			timeout: time.Hour,
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 200*time.Millisecond)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := &Adapter{
				httpClient: &http.Client{Timeout: tt.timeout},
				baseURL:    stallingListener(t),
				tlsConfig:  &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS13},
			}
			ctx, cancel := tt.ctx()
			defer cancel()

			err := bindAgainst(t, ctx, adapter)

			var unavailable *transport.ErrChannelBindingUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want ErrChannelBindingUnavailable", err)
			}
			var timedOut platform.ErrTimeout
			if !errors.As(err, &timedOut) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v, want a REST bound dial timeout", err)
			}
		})
	}
}

func TestBindChannel_ClosedAdapter(t *testing.T) {
	adapter := &Adapter{httpClient: &http.Client{}, baseURL: "https://127.0.0.1:1"}
	adapter.closed.Store(true)

	_, err := adapter.bindChannel(context.Background(), func(context.Context, []byte) error { return nil })

	if !errors.As(err, new(ErrClientClosed)) {
		t.Fatalf("err = %v, want ErrClientClosed", err)
	}
}
