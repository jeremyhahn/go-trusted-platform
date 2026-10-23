package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// statusBodies are the shapes GET /api/v1/status answers with: the
// unauthenticated liveness body (string status, RFC 3339 timestamp, an uptime
// string with no proto field) and the platform handler body (integer unix
// timestamp, a nested system block). Neither is protojson.
var statusBodies = map[string]string{
	"liveness": `{"success":true,"code":200,"payload":{"status":"ready","uptime":"5m3s","timestamp":"2026-10-11T10:00:00Z"}}`,
	"platform": `{"success":true,"code":200,"payload":{"status":"ready","version":"1.2.3","build_time":"x",` +
		`"git_commit":"abc","go_version":"go1.27","system":{"os":"linux","arch":"amd64","num_cpus":8,` +
		`"total_memory_mb":16384,"available_memory_mb":8192,"uptime":"1h"},"timestamp":1791713000}}`,
}

func connectTo(t *testing.T, h http.Handler) *restClientConn {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)

	adapter, err := Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer(server)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })

	conn, ok := adapter.Connection().(*restClientConn)
	require.True(t, ok)
	return conn
}

func TestInvokeGetStatus_DecodesServerBodies(t *testing.T) {
	for name, body := range statusBodies {
		t.Run(name, func(t *testing.T) {
			conn := connectTo(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" { // Connect's liveness probe
					return
				}
				assert.Equal(t, "/api/v1/status", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))

			var resp platformv1.GetStatusResponse
			err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetStatus", &platformv1.GetStatusRequest{}, &resp)
			require.NoError(t, err)
			assert.Equal(t, platformv1.SystemStatus_SYSTEM_STATUS_READY, resp.GetStatus())
			assert.NotNil(t, resp.GetTimestamp())
		})
	}
}

func TestInvokeGetStatus_RejectsUnknownStatus(t *testing.T) {
	conn := connectTo(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"code":200,"payload":{"status":"bogus","timestamp":"2026-10-11T10:00:00Z"}}`))
	}))

	var resp platformv1.GetStatusResponse
	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetStatus", &platformv1.GetStatusRequest{}, &resp)
	require.Error(t, err)
}

func TestMapGRPCMethodToREST_GetHealthIsExplicit(t *testing.T) {
	path, method := mapGRPCMethodToREST("/platform.v1.PlatformDaemon/GetHealth")
	assert.Equal(t, "/health", path)
	assert.Equal(t, http.MethodGet, method)

	_, declared := grpcMethodToRESTMap["/platform.v1.PlatformDaemon/GetHealth"]
	assert.True(t, declared, "GetHealth must be mapped explicitly, not by the derived fallback")
}
