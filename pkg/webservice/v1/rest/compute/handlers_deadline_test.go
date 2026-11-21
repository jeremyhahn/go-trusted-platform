// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package compute

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// lifecycleComputeServer answers the VM lifecycle RPCs at once.
type lifecycleComputeServer struct {
	platformv1.UnimplementedComputeServiceServer
}

func (lifecycleComputeServer) StartVM(context.Context, *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	return &platformv1.StartVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (lifecycleComputeServer) StopVM(context.Context, *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	return &platformv1.StopVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (lifecycleComputeServer) RebootVM(context.Context, *platformv1.RebootVMRequest) (*platformv1.RebootVMResponse, error) {
	return &platformv1.RebootVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (lifecycleComputeServer) MigrateVM(context.Context, *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	return &platformv1.MigrateVMResponse{}, nil
}

// serveWithExpiredWriteDeadline serves the compute routes from a server whose
// write timeout has passed by the time any handler runs, as a graceful stop
// that outlasts the platform's 30 s write timeout leaves it.
func serveWithExpiredWriteDeadline(t *testing.T) *httptest.Server {
	t.Helper()
	root := mux.NewRouter()
	NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), lifecycleComputeServer{}, newTestWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	server := httptest.NewUnstartedServer(root)
	server.Config.WriteTimeout = time.Nanosecond
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func postLifecycle(server *httptest.Server, action, body string) (*http.Response, error) {
	return server.Client().Post(server.URL+"/api/v1/compute/vms/vm-1/"+action,
		"application/json", strings.NewReader(body))
}

// Stop and reboot wait on the guest; migrate waits on the transfer and the
// receiver's finalize, which the UI allows an hour for.
func TestComputeHandlers_LongRoutesOutliveTheWriteTimeout(t *testing.T) {
	server := serveWithExpiredWriteDeadline(t)

	for action, body := range map[string]string{
		"stop":    `{"timeoutSeconds":30}`,
		"reboot":  `{}`,
		"migrate": `{"destinationHost":"dest-1"}`,
	} {
		t.Run(action, func(t *testing.T) {
			resp, err := postLifecycle(server, action, body)
			require.NoError(t, err, "the reply must reach the client after the write timeout")
			defer resp.Body.Close()
			reply, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, string(reply))
		})
	}
}

// A route that does not wait on the guest keeps the server's write timeout,
// so the same server drops its reply: the deadline above is what saves stop
// and reboot.
func TestComputeHandlers_StartKeepsTheWriteTimeout(t *testing.T) {
	server := serveWithExpiredWriteDeadline(t)

	resp, err := postLifecycle(server, "start", `{}`)
	if err == nil {
		resp.Body.Close()
	}
	require.Error(t, err, "a reply written after the write deadline must not reach the client")
}

// A response writer that cannot move its deadline (the recorder here) still
// gets the reply: the handler logs the refusal and serves the request.
func TestComputeHandlers_StopAnswersWhenTheDeadlineCannotMove(t *testing.T) {
	root := mux.NewRouter()
	NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), lifecycleComputeServer{}, newTestWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/stop", strings.NewReader(`{"force":true}`))
	req.Header.Set("Content-Type", "application/json")
	root.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}
