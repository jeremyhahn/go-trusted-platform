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

package rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// serveComputeWithExpiredWriteDeadline serves the compute routes from a
// server whose write timeout has passed by the time any handler runs, as a
// graceful stop that outlasts the daemon's 30 s REST write timeout leaves it.
func serveComputeWithExpiredWriteDeadline(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(computeRouter(&fakeComputeService{}))
	server.Config.WriteTimeout = time.Nanosecond
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func postVMAction(t *testing.T, server *httptest.Server, action, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+computeBasePath+"/vms/vm-1/"+action, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Content-Type", "application/json")
	return server.Client().Do(req)
}

func TestComputeHandlers_StopAndRebootOutliveTheWriteTimeout(t *testing.T) {
	server := serveComputeWithExpiredWriteDeadline(t)

	for action, body := range map[string]string{
		"stop":   `{"timeoutSeconds":30}`,
		"reboot": `{}`,
	} {
		t.Run(action, func(t *testing.T) {
			resp, err := postVMAction(t, server, action, body)
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
	server := serveComputeWithExpiredWriteDeadline(t)

	resp, err := postVMAction(t, server, "start", `{}`)
	if err == nil {
		resp.Body.Close()
	}
	require.Error(t, err, "a reply written after the write deadline must not reach the client")
}

// A response writer that cannot move its deadline (the recorder here) still
// gets the reply: the handler logs the refusal and serves the request.
func TestComputeHandlers_StopAnswersWhenTheDeadlineCannotMove(t *testing.T) {
	rec := serveCompute(computeRouter(&fakeComputeService{}), http.MethodPost, computeBasePath+"/vms/vm-1/stop", `{"force":true}`)

	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestStopVMOptions(t *testing.T) {
	tests := []struct {
		name string
		req  *platformv1.StopVMRequest
		want compute.StopOptions
	}{
		{name: "graceful with a timeout", req: &platformv1.StopVMRequest{TimeoutSeconds: 90}, want: compute.StopOptions{Timeout: 90 * time.Second}},
		{name: "forced", req: &platformv1.StopVMRequest{Force: true}, want: compute.StopOptions{Force: true}},
		{name: "the zero request is the default stop", req: &platformv1.StopVMRequest{}, want: compute.StopOptions{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stopVMOptions(tt.req))
		})
	}
}

func TestRebootVMOptions(t *testing.T) {
	assert.Equal(t, compute.StopOptions{Force: true}, rebootVMOptions(&platformv1.RebootVMRequest{Force: true}))
	assert.Equal(t, compute.StopOptions{}, rebootVMOptions(&platformv1.RebootVMRequest{}), "a reboot's stop half waits the default window")
}
