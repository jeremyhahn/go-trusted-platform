package daemon

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// iamRESTRemoteServer mounts the IAM routes over a remote (gRPC or Unix)
// QuicBaaS backend, which serves the operations the embedded transport
// cannot.
func iamRESTRemoteServer(t *testing.T) *RESTServer {
	t.Helper()
	iam := newMemIAM()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(iamRESTCallers, nil, nil)
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewRemoteQuicBaaSIAMAdapter(iam), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant, false))
	return s
}

func TestIAMREST_RemoteBackendServesRoutesAwaitingSDK(t *testing.T) {
	s := iamRESTRemoteServer(t)
	placeholders := strings.NewReplacer("{tenant}", iamRESTTenantA, "{id}", "x1", "{role}", "r1", "{user}", "u1")
	for key := range iamRoutesAwaitingSDK {
		t.Run(key.method+" "+key.template, func(t *testing.T) {
			path := placeholders.Replace(key.template)
			if !strings.Contains(key.template, "{tenant}") {
				// The flat form names its tenant in the query, as the
				// served flat routes do.
				path += "?tenant_id=" + iamRESTTenantA
			}
			recorder := serveIAM(s, key.method, path, "operator")
			assertReachedHandler(t, recorder)
			assert.Equal(t, http.StatusUnauthorized, serveIAM(s, key.method, path, "").Code)
		})
	}
}
