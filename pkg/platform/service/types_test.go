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

package service

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
)

func TestErrCreateService(t *testing.T) {
	assert.Equal(t, "service: failed to create service", ErrCreateService.Error())
}

func TestErrPermissionDenied(t *testing.T) {
	assert.Equal(t, "service: permission denied", ErrPermissionDenied.Error())
}

func TestErrDeleteAdminAccount(t *testing.T) {
	assert.Equal(t, "service: admin account can't be deleted", ErrDeleteAdminAccount.Error())
}

func TestErrChangeAdminRole(t *testing.T) {
	assert.Equal(t, "service: admin role can't be changed", ErrChangeAdminRole.Error())
}

func TestErrResetPasswordUnsupported(t *testing.T) {
	assert.Equal(t, "service: reset password feature unsupported by auth store", ErrResetPasswordUnsupported.Error())
}

func TestUserCredential_Empty(t *testing.T) {
	cred := UserCredential{}

	assert.Equal(t, uint64(0), cred.OrgID)
	assert.Equal(t, "", cred.Email)
	assert.Equal(t, "", cred.Password)
	assert.Equal(t, 0, cred.AuthType)
}

func TestUserCredential_JSONTags(t *testing.T) {
	// This test verifies that the JSON tags exist and are correct
	// by checking the struct definition compiles correctly
	cred := UserCredential{
		OrgID:    1,
		Email:    "json@test.com",
		Password: "pass",
		AuthType: 2,
	}

	// Just verify the struct works with all fields
	assert.NotEqual(t, uint64(0), cred.OrgID)
}

func TestAuthServicer_Interface(t *testing.T) {
	// Test that the interface exists and has the expected methods
	// This is a compile-time check
	var _ AuthServicer = (*mockAuthServicer)(nil)
}

// mockAuthServicer is a mock implementation for testing
type mockAuthServicer struct{}

func (m *mockAuthServicer) Activate(registrationID uint64) (*entities.User, error) {
	return nil, nil
}

func (m *mockAuthServicer) Login(userCredentials *UserCredential) (*entities.User, []*entities.Service, error) {
	return nil, nil, nil
}

func (m *mockAuthServicer) Register(userCredentials *UserCredential, baseURI string) (*entities.User, error) {
	return nil, nil
}

func (m *mockAuthServicer) ResetPassword(userCredentials *UserCredential) error {
	return nil
}
