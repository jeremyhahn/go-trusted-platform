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
	"crypto/x509"
	"net"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
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

// MockPolicyEngine is a mock implementation of policy.PolicyEngine
type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	args := m.Called(portID, state)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	args := m.Called(portID)
	return args.Get(0).(policy.PortState), args.Error(1)
}

func (m *MockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	args := m.Called(portID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*policy.PortInfo), args.Error(1)
}

func (m *MockPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	args := m.Called(portID, pol)
	return args.Error(0)
}

func (m *MockPolicyEngine) RemovePolicy(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	args := m.Called(portID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*policy.PortPolicy), args.Error(1)
}

func (m *MockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	args := m.Called(portID, cert)
	return args.Error(0)
}

func (m *MockPolicyEngine) OnCertificateExpired(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) OnCertificateRevoked(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) BlockPort(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) UnblockPort(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetOFPort(portID string) (int32, error) {
	args := m.Called(portID)
	return args.Get(0).(int32), args.Error(1)
}

func (m *MockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	args := m.Called(portID, vlan)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	args := m.Called(portID)
	return args.Get(0).(uint16), args.Error(1)
}

func (m *MockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*policy.CertificateMonitor)
}

// MockARPTable is a mock implementation of arp.Table
type MockARPTable struct {
	mock.Mock
}

func (m *MockARPTable) LookupMAC(ipAddr string) (net.HardwareAddr, error) {
	args := m.Called(ipAddr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(net.HardwareAddr), args.Error(1)
}

func (m *MockARPTable) LookupIP(macAddr string) (net.IP, error) {
	args := m.Called(macAddr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(net.IP), args.Error(1)
}

func (m *MockARPTable) Entries() ([]arp.Entry, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]arp.Entry), args.Error(1)
}

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
