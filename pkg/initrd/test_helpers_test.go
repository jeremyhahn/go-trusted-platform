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

package initrd

import (
	"context"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"github.com/stretchr/testify/mock"
)

// MockTPM is a mock implementation of TrustedPlatformModule
type MockTPM struct {
	mock.Mock
}

func (m *MockTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xkmssdk.KeyAttributes), args.Error(1)
}

func (m *MockTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*xkmssdk.KeyAttributes), args.Error(1)
}

func (m *MockTPM) Install(soPIN xkmssdk.Password) error {
	args := m.Called(soPIN)
	return args.Error(0)
}

func (m *MockTPM) Seal(keyAttrs *xkmssdk.KeyAttributes, keyBackend xkmssdk.TPMKeyBackend, overwrite bool) (interface{}, error) {
	args := m.Called(keyAttrs, keyBackend, overwrite)
	return args.Get(0), args.Error(1)
}

func (m *MockTPM) Unseal(keyAttrs *xkmssdk.KeyAttributes, keyBackend xkmssdk.TPMKeyBackend) ([]byte, error) {
	args := m.Called(keyAttrs, keyBackend)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTPM) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockLUKSHandler is a mock implementation of LUKS Handler
type MockLUKSHandler struct {
	mock.Mock
}

func (m *MockLUKSHandler) IsLUKS(ctx context.Context, devicePath string) (bool, error) {
	args := m.Called(ctx, devicePath)
	return args.Bool(0), args.Error(1)
}

func (m *MockLUKSHandler) Format(ctx context.Context, devicePath string, password []byte, opts *luks.FormatOptions) error {
	args := m.Called(ctx, devicePath, password, opts)
	return args.Error(0)
}

func (m *MockLUKSHandler) AddKey(ctx context.Context, devicePath string, existingPassword, newPassword []byte, opts *luks.AddKeyOptions) error {
	args := m.Called(ctx, devicePath, existingPassword, newPassword, opts)
	return args.Error(0)
}

func (m *MockLUKSHandler) Open(ctx context.Context, devicePath, mappingName string, password []byte, opts *luks.OpenOptions) error {
	args := m.Called(ctx, devicePath, mappingName, password, opts)
	return args.Error(0)
}

func (m *MockLUKSHandler) IsOpen(ctx context.Context, mappingName string) bool {
	args := m.Called(ctx, mappingName)
	return args.Bool(0)
}

func (m *MockLUKSHandler) Close(ctx context.Context, mappingName string) error {
	args := m.Called(ctx, mappingName)
	return args.Error(0)
}

func (m *MockLUKSHandler) Status(ctx context.Context, devicePath string) (*luks.VolumeStatus, error) {
	args := m.Called(ctx, devicePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*luks.VolumeStatus), args.Error(1)
}

func (m *MockLUKSHandler) Version(ctx context.Context, devicePath string) (luks.LUKSVersion, error) {
	args := m.Called(ctx, devicePath)
	return args.Get(0).(luks.LUKSVersion), args.Error(1)
}

func (m *MockLUKSHandler) RemoveKey(ctx context.Context, devicePath string, slot int) error {
	args := m.Called(ctx, devicePath, slot)
	return args.Error(0)
}

func (m *MockLUKSHandler) KillSlot(ctx context.Context, devicePath string, slot int) error {
	args := m.Called(ctx, devicePath, slot)
	return args.Error(0)
}

func (m *MockLUKSHandler) ChangeKey(ctx context.Context, devicePath string, slot int, oldPassword, newPassword []byte) error {
	args := m.Called(ctx, devicePath, slot, oldPassword, newPassword)
	return args.Error(0)
}

func (m *MockLUKSHandler) UUID(ctx context.Context, devicePath string) (string, error) {
	args := m.Called(ctx, devicePath)
	return args.String(0), args.Error(1)
}

func (m *MockLUKSHandler) DumpHeader(ctx context.Context, devicePath string) (map[string]interface{}, error) {
	args := m.Called(ctx, devicePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockLUKSHandler) TestKey(ctx context.Context, devicePath string, password []byte, slot *int) error {
	args := m.Called(ctx, devicePath, password, slot)
	return args.Error(0)
}

func (m *MockLUKSHandler) Resize(ctx context.Context, mappingName string, newSize *uint64) error {
	args := m.Called(ctx, mappingName, newSize)
	return args.Error(0)
}

func (m *MockLUKSHandler) Suspend(ctx context.Context, mappingName string) error {
	args := m.Called(ctx, mappingName)
	return args.Error(0)
}

func (m *MockLUKSHandler) Resume(ctx context.Context, mappingName string, password []byte) error {
	args := m.Called(ctx, mappingName, password)
	return args.Error(0)
}

// MockKeyBackend is a mock implementation of KeyBackend
type MockKeyBackend struct {
	mock.Mock
}

func (m *MockKeyBackend) Close() error {
	args := m.Called()
	return args.Error(0)
}

// createTestPlatform creates a minimal test platform for unit testing
// TPM is nil since we don't need full TPM operations for most unit tests
func createTestPlatform() *Platform {
	mockLUKS := &MockLUKSHandler{}

	return &Platform{
		TPM:  nil, // TPM operations require full implementation
		LUKS: mockLUKS,
		Config: &Config{
			RootDevice:      "/dev/sda2",
			XKMSPath:        "/var/lib/test/xkms",
			PCRBanks:        []string{"sha256"},
			PCRSelection:    []uint{0, 1, 2, 3, 7},
			UnlockTimeout:   30,
			FallbackMethods: []luks.UnlockMethod{luks.UnlockTPMPCR, luks.UnlockPassword},
		},
	}
}
