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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateRecord_AcceptsValidRecords(t *testing.T) {
	cases := []struct {
		recordType, name, value string
	}{
		{"A", "www", "192.0.2.1"},
		{"a", "@", "10.0.0.1"},
		{"AAAA", "www", "2001:db8::1"},
		{"AAAA", "www.example.com.", "::ffff:192.0.2.1"},
		{"CNAME", "alias", "www.example.com."},
		{"TXT", "@", "not-an-ip"},
		{"SRV", "_sip._tcp", ""},
	}
	for _, tc := range cases {
		assert.NoError(t, ValidateRecord(tc.recordType, tc.name, tc.value), "%s %s %q", tc.recordType, tc.name, tc.value)
	}
}

func TestValidateRecord_RefusesEmptyName(t *testing.T) {
	for _, recordType := range []string{"A", "aaaa", "CNAME", "TXT", "TLSA"} {
		err := ValidateRecord(recordType, "", "192.0.2.1")
		var required ErrRecordNameRequired
		require.True(t, errors.As(err, &required), "%s: err = %v", recordType, err)
		assert.Contains(t, err.Error(), "@")
	}
}

func TestValidateRecord_RefusesAnAddressOfTheWrongFamily(t *testing.T) {
	cases := []struct {
		recordType, value, family string
	}{
		{"A", "not-an-ip", "IPv4"},
		{"A", "", "IPv4"},
		{"A", "2001:db8::1", "IPv4"},
		{"A", "::ffff:192.0.2.1", "IPv4"},
		{"A", "192.0.2.256", "IPv4"},
		{"AAAA", "192.168.1.1", "IPv6"},
		{"AAAA", "not-an-ip", "IPv6"},
		{"aaaa", "fe80::1%eth0", "IPv6"},
	}
	for _, tc := range cases {
		err := ValidateRecord(tc.recordType, "host", tc.value)
		var invalid ErrInvalidRecordAddress
		require.True(t, errors.As(err, &invalid), "%s %q: err = %v", tc.recordType, tc.value, err)
		assert.Equal(t, tc.value, invalid.Value)
		assert.Contains(t, err.Error(), tc.family)
	}
}

func TestRecordErrors_AreInvalidArgumentOnEveryTransport(t *testing.T) {
	refusals := []error{
		ValidateRecord("A", "", "192.0.2.1"),
		ValidateRecord("A", "host", "not-an-ip"),
		ValidateTLSAUsage(TLSAUsageMax + 1),
	}
	for _, err := range refusals {
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		assert.Equal(t, err.Error(), status.Convert(err).Message())
	}
	assert.Equal(t, codes.OK, status.Code(ValidateRecord("A", "host", "192.0.2.1")))
}
