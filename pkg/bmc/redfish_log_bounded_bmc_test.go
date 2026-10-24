package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedfishClient_DoGETBounded(t *testing.T) {
	const path = "/redfish/v1/Systems/1/LogServices/SEL/Entries"
	type page struct {
		Name string `json:"Name"`
	}
	tests := []struct {
		name    string
		handler http.HandlerFunc
		ctx     func() context.Context
		check   func(t *testing.T, got page, err error)
	}{
		{
			name: "decodes a page within the limit",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, page{Name: "Log Entries"})
			},
			check: func(t *testing.T, got page, err error) {
				if err != nil {
					t.Fatalf("doGETBounded: %v", err)
				}
				if got.Name != "Log Entries" {
					t.Errorf("Name = %q, want %q", got.Name, "Log Entries")
				}
			},
		},
		{
			name:    "request fails before a response",
			handler: func(http.ResponseWriter, *http.Request) {},
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			check: func(t *testing.T, _ page, err error) {
				var reqErr ErrRedfishRequest
				if !errors.As(err, &reqErr) || !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want ErrRedfishRequest wrapping context.Canceled", err)
				}
			},
		},
		{
			name: "body cut short",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				conn, buf, err := http.NewResponseController(w).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				// Declare more body than is sent, then drop the connection.
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
					"Content-Length: 64\r\n\r\n{\"Name\":")
				_ = buf.Flush()
			},
			check: func(t *testing.T, _ page, err error) {
				var reqErr ErrRedfishRequest
				if !errors.As(err, &reqErr) || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("error = %v, want ErrRedfishRequest wrapping io.ErrUnexpectedEOF", err)
				}
				if reqErr.Path != path {
					t.Errorf("Path = %q, want %q", reqErr.Path, path)
				}
			},
		},
		{
			name: "body is not JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("<html>maintenance</html>"))
			},
			check: func(t *testing.T, _ page, err error) {
				var reqErr ErrRedfishRequest
				var syntaxErr *json.SyntaxError
				if !errors.As(err, &reqErr) || !errors.As(err, &syntaxErr) {
					t.Fatalf("error = %v, want ErrRedfishRequest wrapping a JSON syntax error", err)
				}
			},
		},
		{
			name: "error status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			check: func(t *testing.T, _ page, err error) {
				var reqErr ErrRedfishRequest
				if !errors.As(err, &reqErr) || reqErr.StatusCode != http.StatusInternalServerError {
					t.Fatalf("error = %v, want ErrRedfishRequest with status 500", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(tt.handler)
			t.Cleanup(srv.Close)
			c := newTestRedfishClient(t, srv)
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			var got page
			err := c.doGETBounded(ctx, path, &got, 1024)
			tt.check(t, got, err)
		})
	}
}

func TestRedfishClient_GetEventLog_LogServiceReadFailures(t *testing.T) {
	const selPath = "/redfish/v1/Systems/1/LogServices/SEL"
	tests := []struct {
		name          string
		failPath      string
		wantOperation string
	}{
		{
			name:          "log services collection fails",
			failPath:      "/redfish/v1/Systems/1/LogServices",
			wantOperation: "log services",
		},
		{
			name:          "log service member fails",
			failPath:      selPath,
			wantOperation: "log service " + selPath,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := multiNICRedfishMux(nil)
			mux.HandleFunc("/redfish/v1/Systems/1/LogServices", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: selPath}}})
			})
			mux.HandleFunc(selPath, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, map[string]string{"Id": "SEL", "LogEntryType": "SEL"})
			})
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.failPath {
					http.Error(w, "forced failure", http.StatusInternalServerError)
					return
				}
				mux.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)
			c := newTestRedfishClient(t, srv)

			got, err := c.GetEventLog(context.Background())
			if got != nil {
				t.Errorf("returned a log on a failed read: %+v", got)
			}
			var readErr ErrEventLogRead
			if !errors.As(err, &readErr) {
				t.Fatalf("error = %v, want ErrEventLogRead", err)
			}
			if readErr.Operation != tt.wantOperation {
				t.Errorf("Operation = %q, want %q", readErr.Operation, tt.wantOperation)
			}
			var reqErr ErrRedfishRequest
			if !errors.As(err, &reqErr) || reqErr.StatusCode != http.StatusInternalServerError {
				t.Errorf("error = %v, want the 500 from %s underneath", err, tt.failPath)
			}
		})
	}
}
