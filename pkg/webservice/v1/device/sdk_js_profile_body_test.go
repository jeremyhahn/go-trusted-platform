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

package device

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func createProfileFromJSON(t *testing.T, body string) (*httptest.ResponseRecorder, *mockProfileService) {
	t.Helper()
	handler, _, profileSvc := newTestHandler()
	req := httptest.NewRequest(http.MethodPost, "/device/profiles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.CreateProfile(rec, req)
	return rec, profileSvc
}

// TestCreateProfile_JavaScriptSDKBody feeds the body the JavaScript SDK's
// createProfile sends (sdk/javascript/src/services/device-service.ts): flat,
// with the auth method spelled as profile_mapping.go parses it.
func TestCreateProfile_JavaScriptSDKBody(t *testing.T) {
	rec, profileSvc := createProfileFromJSON(t,
		`{"id":"77","name":"p1","role":"worker","networks":{"trusted":{"vlan":20,"auth_method":"802.1x","zone":"lan"}}}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	stored := profileSvc.profiles[77]
	require.NotNil(t, stored)
	assert.Equal(t, "p1", stored.Name)
	require.Contains(t, stored.Networks, "trusted")
	assert.Equal(t, entities.AuthMethod802_1X, stored.Networks["trusted"].AuthMethod)
	assert.Equal(t, "lan", stored.Networks["trusted"].Zone)
	assert.Equal(t, uint16(20), stored.Networks["trusted"].VLAN)
}

// TestCreateProfile_ShortAuthMethodIsNoAuth pins why the SDK maps the name:
// the '802_1X' it used to send is read as no authentication.
func TestCreateProfile_ShortAuthMethodIsNoAuth(t *testing.T) {
	rec, profileSvc := createProfileFromJSON(t,
		`{"id":"78","name":"p2","role":"worker","networks":{"trusted":{"vlan":20,"auth_method":"802_1X"}}}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	stored := profileSvc.profiles[78]
	require.NotNil(t, stored)
	assert.Equal(t, entities.AuthMethodNone, stored.Networks["trusted"].AuthMethod)
}

// TestCreateProfile_WrappedBodyLosesTheProfile pins why the SDK unwraps the
// request: the {profile:{...}} shape it used to send never reaches the fields,
// so the server stores an empty profile under a generated id.
func TestCreateProfile_WrappedBodyLosesTheProfile(t *testing.T) {
	rec, profileSvc := createProfileFromJSON(t, `{"profile":{"id":"79","name":"p3"}}`)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.NotContains(t, profileSvc.profiles, uint64(79))
	require.Len(t, profileSvc.profiles, 1)
	for _, stored := range profileSvc.profiles {
		assert.Empty(t, stored.Name)
	}
}
