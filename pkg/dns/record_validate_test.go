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

package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

func TestValidateRecordName(t *testing.T) {
	assert.NoError(t, ValidateRecordName("www.example.com."))
	assert.ErrorIs(t, ValidateRecordName(""), ErrRecordNameRequired)
}

func TestValidateARecordValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "ipv4", value: "192.0.2.10"},
		{name: "not an address", value: "not-an-ip", wantErr: ErrInvalidIPv4Address},
		{name: "empty", value: "", wantErr: ErrInvalidIPv4Address},
		{name: "ipv6", value: "2001:db8::1", wantErr: ErrInvalidIPv4Address},
		{name: "ipv4-mapped ipv6", value: "::ffff:192.0.2.10", wantErr: ErrInvalidIPv4Address},
		{name: "octet out of range", value: "256.1.1.1", wantErr: ErrInvalidIPv4Address},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateARecordValue(tc.value)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Contains(t, err.Error(), tc.value)
		})
	}
}

func TestValidateAAAARecordValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "ipv6", value: "2001:db8::1"},
		{name: "loopback", value: "::1"},
		{name: "not an address", value: "not-an-ip", wantErr: ErrInvalidIPv6Address},
		{name: "empty", value: "", wantErr: ErrInvalidIPv6Address},
		{name: "ipv4", value: "192.0.2.10", wantErr: ErrInvalidIPv6Address},
		{name: "ipv4-mapped ipv6", value: "::ffff:192.0.2.10", wantErr: ErrInvalidIPv6Address},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAAAARecordValue(tc.value)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestValidateRecordValue(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		value      string
		wantErr    error
	}{
		{name: "A ipv4", recordType: "A", value: "192.0.2.10"},
		{name: "lower-case a", recordType: "a", value: "not-an-ip", wantErr: ErrInvalidIPv4Address},
		{name: "A ipv6", recordType: "A", value: "2001:db8::1", wantErr: ErrInvalidIPv4Address},
		{name: "AAAA ipv6", recordType: "AAAA", value: "2001:db8::1"},
		{name: "AAAA ipv4", recordType: "AAAA", value: "192.0.2.10", wantErr: ErrInvalidIPv6Address},
		{name: "type without a value syntax", recordType: "TXT", value: "anything"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRecordValue(tc.recordType, tc.value)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestValidateTLSAUsage(t *testing.T) {
	for usage := uint32(0); usage <= maxTLSAUsage; usage++ {
		assert.NoError(t, ValidateTLSAUsage(usage), "usage %d", usage)
	}
	assert.ErrorIs(t, ValidateTLSAUsage(maxTLSAUsage+1), ErrInvalidTLSAUsage)
	assert.ErrorIs(t, ValidateTLSAUsage(255), ErrInvalidTLSAUsage)
}

func TestFindRecord(t *testing.T) {
	rs := &entities.RecordSet{
		ARecords:    []*entities.ARecord{{Name: "www.example.com.", Value: "192.0.2.10", TTL: 300}},
		TLSARecords: []*entities.TLSARecord{{Name: "_443._tcp.example.com.", Usage: 3, Data: "abcd"}},
	}

	found, err := FindRecord(rs, "A", "www.example.com.")
	require.NoError(t, err)
	assert.Same(t, rs.ARecords[0], found)

	found, err = FindRecord(rs, "TLSA", "_443._tcp.example.com.")
	require.NoError(t, err)
	assert.Same(t, rs.TLSARecords[0], found)
}

func TestFindRecord_Errors(t *testing.T) {
	rs := &entities.RecordSet{
		ARecords: []*entities.ARecord{{Name: "www.example.com.", Value: "192.0.2.10"}},
	}

	tests := []struct {
		name       string
		recordType string
		recordName string
		wantErr    error
	}{
		{name: "missing name", recordType: "A", recordName: "mail.example.com.", wantErr: ErrRecordNotFound},
		{name: "name held under another type", recordType: "AAAA", recordName: "www.example.com.", wantErr: ErrRecordNotFound},
		{name: "unsupported type", recordType: "BOGUS", recordName: "www.example.com.", wantErr: ErrRecordTypeNotSupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found, err := FindRecord(rs, tc.recordType, tc.recordName)
			assert.Nil(t, found)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
