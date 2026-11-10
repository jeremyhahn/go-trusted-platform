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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrorMessages pins the message of every typed error, with and without
// its optional cause or reason, since handlers send these to the client.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrMissingRole{}, "device: role is required"},
		{ErrMissingTemplate{}, "device: template payload is required"},
		{ErrInvalidRequestBody{Reason: "unexpected EOF"}, "device: invalid request body: unexpected EOF"},
		{ErrInvalidRequestBody{}, "device: invalid request body"},
		{ErrInvalidTemplateID{}, "device: invalid template id"},
		{ErrTemplateSaveFailed{Cause: errors.New("disk full")}, "device: failed to save template: disk full"},
		{ErrTemplateSaveFailed{}, "device: failed to save template"},
		{ErrProfileCreateFailed{Cause: errors.New("not found")}, "device: failed to create profile: not found"},
		{ErrProfileCreateFailed{}, "device: failed to create profile"},
		{ErrProfileSaveFailed{Cause: errors.New("constraint violation")}, "device: failed to save profile: constraint violation"},
		{ErrProfileSaveFailed{}, "device: failed to save profile"},
		{ErrTemplateServiceNil{}, "device: template service not initialized"},
		{ErrProfileServiceNil{}, "device: profile service not initialized"},
		{ErrMissingHostname{}, "device: hostname is required"},
		{ErrInvalidProfileConfig{Cause: ErrProfileConfigNull{}}, "device: profile config must be a JSON object: config is null"},
		{ErrEKCertNotAccepted{}, "device: ek_cert is not accepted on the unauthenticated create-profile route; bind the EK via POST /api/v1/device/profiles/{id}/assign"},
		{ErrMissingDeviceIdentifier{}, "device: at least one of mac or serial query parameter is required"},
		{ErrProfileNotFound{MAC: "aa:bb:cc:dd:ee:ff", Serial: "SN123"}, "device: no matching profile found for mac=aa:bb:cc:dd:ee:ff serial=SN123"},
		{ErrProfileConfigEmpty{ProfileID: 42}, "device: profile has no config"},
		{ErrConfigMarshalFailed{Cause: errors.New("unsupported type")}, "device: failed to marshal config: unsupported type"},
		{ErrConfigMarshalFailed{}, "device: failed to marshal config"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

// TestErrInvalidProfileConfig_Unwrap verifies the cause stays reachable
// through errors.Is and errors.As.
func TestErrInvalidProfileConfig_Unwrap(t *testing.T) {
	cause := errors.New("json: cannot unmarshal array")
	assert.ErrorIs(t, ErrInvalidProfileConfig{Cause: cause}, cause)
	assert.ErrorAs(t, ErrInvalidProfileConfig{Cause: ErrProfileConfigNull{}}, &ErrProfileConfigNull{})
}
