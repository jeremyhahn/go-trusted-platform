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
	"context"
	"net/http"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
	"github.com/stretchr/testify/mock"
)

// MockProfileService is a mock implementation of ProfileService
type MockProfileService struct {
	mock.Mock
}

func (m *MockProfileService) GetBySerial(ctx context.Context, serial string) (*ProfileResponse, error) {
	args := m.Called(ctx, serial)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ProfileResponse), args.Error(1)
}

// MockDeviceActivator is a mock implementation of DeviceActivator.
// LockSerial is a real mutex rather than a testify expectation so every
// test exercises the handler's lock/unlock sequence without boilerplate.
type MockDeviceActivator struct {
	mock.Mock
	serialMu sync.Mutex
}

func (m *MockDeviceActivator) LockSerial(serial string) (unlock func()) {
	m.serialMu.Lock()
	return m.serialMu.Unlock
}

func (m *MockDeviceActivator) PrecheckActivation(serial string) (policy.ActivationPlan, error) {
	args := m.Called(serial)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(policy.ActivationPlan), args.Error(1)
}

func (m *MockDeviceActivator) ActivateDevice(plan policy.ActivationPlan) (*policy.ActivationResult, error) {
	args := m.Called(plan)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*policy.ActivationResult), args.Error(1)
}

func (m *MockDeviceActivator) FinalizeActivation(plan policy.ActivationPlan) {
	m.Called(plan)
}

func (m *MockDeviceActivator) ReinstateActivation(plan policy.ActivationPlan) {
	m.Called(plan)
}

// fakeActivationPlan implements policy.ActivationPlan for handler tests:
// the handler only reads the VLAN snapshot and the expected outcome from a
// plan, so orchestration tests fake it rather than driving a real precheck.
type fakeActivationPlan struct {
	serial       string
	vlans        policy.ActivationVLANs
	zoneMismatch *policy.ErrZoneMismatch
}

func (p *fakeActivationPlan) Serial() string                        { return p.serial }
func (p *fakeActivationPlan) VLANs() policy.ActivationVLANs         { return p.vlans }
func (p *fakeActivationPlan) ExpectQuarantine() bool                { return p.zoneMismatch != nil }
func (p *fakeActivationPlan) ZoneMismatch() *policy.ErrZoneMismatch { return p.zoneMismatch }

// MockHttpWriter is a mock implementation of response.HttpWriter
type MockHttpWriter struct {
	mock.Mock
}

func (m *MockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	m.Called(w, r, status, response)
}

func (m *MockHttpWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	m.Called(w, status, response)
}

func (m *MockHttpWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	m.Called(w, status, response)
}

func (m *MockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}

func (m *MockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Success200(w, r, payload)
}

func (m *MockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.Called(w, r, payload, err)
}

func (m *MockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.Called(w, r, err, payload)
}

func (m *MockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error503(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

// MockSwitchService is a mock implementation of SwitchServiceProvider
type MockSwitchService struct {
	mock.Mock
}

func (m *MockSwitchService) Manager(name string) (switchmgmt.Manager, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(switchmgmt.Manager), args.Error(1)
}

// MockSwitchManager is a mock implementation of switchmgmt.Manager
type MockSwitchManager struct {
	mock.Mock
}

func (m *MockSwitchManager) SetPortVLAN(ctx context.Context, port string, vlanID uint16) error {
	args := m.Called(ctx, port, vlanID)
	return args.Error(0)
}

func (m *MockSwitchManager) GetPortVLAN(ctx context.Context, port string) (uint16, error) {
	args := m.Called(ctx, port)
	return args.Get(0).(uint16), args.Error(1)
}

func (m *MockSwitchManager) GetPortStatus(ctx context.Context, port string) (*switchwire.PortStatus, error) {
	args := m.Called(ctx, port)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*switchwire.PortStatus), args.Error(1)
}

func (m *MockSwitchManager) ListPorts(ctx context.Context) ([]*switchwire.PortStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*switchwire.PortStatus), args.Error(1)
}

func (m *MockSwitchManager) EnablePort(ctx context.Context, port string) error {
	args := m.Called(ctx, port)
	return args.Error(0)
}

func (m *MockSwitchManager) DisablePort(ctx context.Context, port string) error {
	args := m.Called(ctx, port)
	return args.Error(0)
}

func (m *MockSwitchManager) Close() error {
	args := m.Called()
	return args.Error(0)
}
