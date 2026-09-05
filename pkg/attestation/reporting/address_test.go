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

package reporting

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDevices struct {
	records map[string]*DeviceAddressRecord
	err     error
}

func (s *stubDevices) AddressRecord(_ context.Context, id string) (*DeviceAddressRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records[id], nil
}

type stubNames struct {
	answers map[string][]string
	err     error
	asked   []string
}

func (s *stubNames) Resolve(_ context.Context, name, rt string) ([]string, error) {
	s.asked = append(s.asked, rt+" "+name)
	if s.err != nil {
		return nil, s.err
	}
	return s.answers[rt+" "+name], nil
}

func TestNewDeviceAddressResolver_FailsClosed(t *testing.T) {
	_, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{Port: 9443})
	var noDevices ErrNoDeviceRecords
	require.ErrorAs(t, err, &noDevices)

	_, err = NewDeviceAddressResolver(DeviceAddressResolverConfig{Devices: &stubDevices{}, Port: 0})
	var badPort ErrInvalidPort
	require.ErrorAs(t, err, &badPort)
	assert.Contains(t, badPort.Error(), "0")
}

func TestEndpoints_PrefersPlatformDNSThenHeartbeatPeer(t *testing.T) {
	devices := &stubDevices{records: map[string]*DeviceAddressRecord{
		"42": {Hostname: "Mini-05-Compute-01", HeartbeatAddr: "198.18.1.143:51234"},
	}}
	names := &stubNames{answers: map[string][]string{
		"A lab-node-5-compute-01.trusted-platform.internal":    {"198.18.0.24"},
		"AAAA lab-node-5-compute-01.trusted-platform.internal": {"2001:db8::24"},
	}}
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{
		Devices: devices, Names: names, InternalDomain: "trusted-platform.internal.", Port: 9443,
	})
	require.NoError(t, err)

	eps, err := r.Endpoints(context.Background(), "42")
	require.NoError(t, err)
	require.Len(t, eps, 3)
	assert.Equal(t, Endpoint{Address: "198.18.0.24:9443", ServerName: "lab-node-5-compute-01.trusted-platform.internal", Source: SourcePlatformDNS}, eps[0])
	assert.Equal(t, Endpoint{Address: "[2001:db8::24]:9443", ServerName: "lab-node-5-compute-01.trusted-platform.internal", Source: SourcePlatformDNS}, eps[1])
	assert.Equal(t, Endpoint{Address: "198.18.1.143:9443", ServerName: "lab-node-5-compute-01.trusted-platform.internal", Source: SourceHeartbeatPeer}, eps[2])
}

func TestEndpoints_HeartbeatOnlyWhenDNSHasNoRecord(t *testing.T) {
	devices := &stubDevices{records: map[string]*DeviceAddressRecord{
		"7": {Hostname: "gw-01.trusted-platform.internal", HeartbeatAddr: "198.18.1.139"},
	}}
	names := &stubNames{}
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{
		Devices: devices, Names: names, InternalDomain: "trusted-platform.internal", Port: 9443,
	})
	require.NoError(t, err)
	eps, err := r.Endpoints(context.Background(), "7")
	require.NoError(t, err)
	require.Len(t, eps, 1)
	assert.Equal(t, "198.18.1.139:9443", eps[0].Address)
	assert.Equal(t, SourceHeartbeatPeer, eps[0].Source)
	// The hostname already carried the zone: it is not appended twice.
	assert.Equal(t, "gw-01.trusted-platform.internal", eps[0].ServerName)
	assert.Contains(t, names.asked, "A gw-01.trusted-platform.internal")
}

func TestEndpoints_FailsClosedWithoutAnyTrustworthyAddress(t *testing.T) {
	devices := &stubDevices{records: map[string]*DeviceAddressRecord{
		"1": {Hostname: "node-01"},
		"2": {Hostname: "node-02", HeartbeatAddr: "not-an-ip:1"},
	}}
	names := &stubNames{err: errors.New("zone missing")}
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{
		Devices: devices, Names: names, InternalDomain: "example.internal", Port: 9443,
	})
	require.NoError(t, err)

	for _, id := range []string{"1", "2", "unknown"} {
		_, err := r.Endpoints(context.Background(), id)
		require.Error(t, err, id)
		var none ErrNoDialableAddress
		require.ErrorAs(t, err, &none, id)
		assert.Equal(t, id, none.DeviceID)
	}
	_, err = r.Endpoints(context.Background(), "1")
	assert.Contains(t, err.Error(), "node-01.example.internal")
}

func TestEndpoints_DeviceLookupErrorIsNotAnAddress(t *testing.T) {
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{
		Devices: &stubDevices{err: errors.New("store down")}, Port: 9443,
	})
	require.NoError(t, err)
	_, err = r.Endpoints(context.Background(), "1")
	var none ErrNoDialableAddress
	require.ErrorAs(t, err, &none)
	assert.Contains(t, none.Reason, "store down")
}

func TestEndpoints_ProfileServerNameOverridesFQDN(t *testing.T) {
	devices := &stubDevices{records: map[string]*DeviceAddressRecord{
		"9": {Hostname: "lab-node-5-compute-01", HeartbeatAddr: "198.18.1.143:1", TLSServerName: " Compute.Trusted-Platform.Internal "},
	}}
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{Devices: devices, InternalDomain: "trusted-platform.internal", Port: 9443})
	require.NoError(t, err)
	eps, err := r.Endpoints(context.Background(), "9")
	require.NoError(t, err)
	require.Len(t, eps, 1)
	assert.Equal(t, "compute.trusted-platform.internal", eps[0].ServerName)
}

func TestEndpoints_NoNameToVerifyAgainstFailsClosed(t *testing.T) {
	devices := &stubDevices{records: map[string]*DeviceAddressRecord{
		"9": {HeartbeatAddr: "198.18.1.143:1"},
	}}
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{Devices: devices, Port: 9443})
	require.NoError(t, err)
	_, err = r.Endpoints(context.Background(), "9")
	var none ErrNoDialableAddress
	require.ErrorAs(t, err, &none)
	assert.Contains(t, none.Reason, "no name")
}

func TestEndpoints_DeduplicatesAndCaps(t *testing.T) {
	devices := &stubDevices{records: map[string]*DeviceAddressRecord{
		"3": {Hostname: "n", HeartbeatAddr: "10.0.0.1:5"},
	}}
	names := &stubNames{answers: map[string][]string{
		"A n.z": {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "bogus"},
	}}
	r, err := NewDeviceAddressResolver(DeviceAddressResolverConfig{Devices: devices, Names: names, InternalDomain: "z", Port: 1})
	require.NoError(t, err)
	eps, err := r.Endpoints(context.Background(), "3")
	require.NoError(t, err)
	assert.Len(t, eps, maxEndpointsPerDevice)
	assert.Equal(t, "10.0.0.1:1", eps[0].Address)
}

func TestHeartbeatHost(t *testing.T) {
	assert.Equal(t, "10.0.0.1", heartbeatHost("10.0.0.1:99"))
	assert.Equal(t, "10.0.0.1", heartbeatHost(" 10.0.0.1 "))
	assert.Equal(t, "2001:db8::1", heartbeatHost("[2001:db8::1]:99"))
	assert.Equal(t, "", heartbeatHost("host.example:99"))
	assert.Equal(t, "", heartbeatHost(""))
}
