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

package daemon

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Both daemon REST surfaces bind a challenge to the bearer token's tenant:
// the guard's verified caller reaches the attest service, so a challenge
// issued under tenant-a is refused to a tenant-b caller (#2142).
func TestDaemonRESTDeviceAttest_ChallengeKeepsTheBearerTenant(t *testing.T) {
	tokens := iamRESTTokens{
		"writer-a": {Subject: "writer-a", TenantID: iamRESTTenantA, Scopes: []string{"device:write"}},
		"writer-b": {Subject: "writer-b", TenantID: iamRESTTenantB, Scopes: []string{"device:write"}},
	}
	guard := restapi.NewScopeGuard(tokens, nil, nil)

	serve := func(s *RESTServer, path, token string, body any) *httptest.ResponseRecorder {
		raw := []byte("{}")
		if body != nil {
			var err error
			raw, err = json.Marshal(body)
			require.NoError(t, err)
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		s.router.ServeHTTP(recorder, req)
		return recorder
	}

	surfaces := []struct {
		name     string
		envelope bool
		mount    func(s *RESTServer, svc *DeviceGRPCService) error
	}{
		{"webservice router", true, func(s *RESTServer, svc *DeviceGRPCService) error {
			return s.SetDeviceRouterHandlers(logging.DefaultLogger(), routeTableDeviceService{}, deviceRESTProfiles{},
				routeTableDeviceTemplates{}, svc, guard)
		}},
		{"device facade", false, func(s *RESTServer, svc *DeviceGRPCService) error {
			return s.SetDeviceHandlers(routeTableDevices{}, routeTableProfiles{}, svc, guard)
		}},
	}

	for _, surface := range surfaces {
		t.Run(surface.name, func(t *testing.T) {
			f := newQuoteFixture(t)
			clock := f.now
			svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			require.NoError(t, surface.mount(s, svc))
			base := "/api/v1/devices/" + itoa(f.device.ID) + "/attest"

			issue := func(t *testing.T, token string) restapi.DeviceAttestChallengeResponse {
				t.Helper()
				w := serve(s, base+"/challenge", token, nil)
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				var ch restapi.DeviceAttestChallengeResponse
				if surface.envelope {
					var env struct {
						Payload restapi.DeviceAttestChallengeResponse `json:"payload"`
					}
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
					ch = env.Payload
				} else {
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ch), w.Body.String())
				}
				require.NotEmpty(t, ch.ChallengeID, w.Body.String())
				require.Len(t, ch.Nonce, 32)
				return ch
			}
			attest := func(t *testing.T, token string, ch restapi.DeviceAttestChallengeResponse) *httptest.ResponseRecorder {
				t.Helper()
				return serve(s, base, token, restapi.DeviceAttestRequest{
					Evidence:    f.evidence(t, ch.Nonce, goldenPCRs()),
					ChallengeID: ch.ChallengeID,
				})
			}

			ch := issue(t, "writer-a")
			w := attest(t, "writer-b", ch)
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

			ch = issue(t, "writer-a")
			w = attest(t, "writer-a", ch)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), `"verified":true`)
		})
	}
}
