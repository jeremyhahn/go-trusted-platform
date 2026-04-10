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
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/stretchr/testify/assert"
)

func TestExpandVar(t *testing.T) {
	// Setup test macros
	macros["TEST_VAR"] = "test-value"
	macros["PUBLIC_IPv4"] = "1.2.3.4"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Expand single variable",
			input:    "${TEST_VAR}",
			expected: "test-value",
		},
		{
			name:     "Expand IP variable",
			input:    "${PUBLIC_IPv4}",
			expected: "1.2.3.4",
		},
		{
			name:     "No variable to expand",
			input:    "plain-text",
			expected: "plain-text",
		},
		{
			name:     "Empty variable returns empty",
			input:    "${NONEXISTENT}",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandVar(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExpandVar_MultipleVariables(t *testing.T) {
	macros["VAR1"] = "value1"
	macros["VAR2"] = "value2"
	result := ExpandVar("${VAR1}${VAR2}")
	assert.Equal(t, "value1value2", result, "Should expand multiple macros")
}

func TestSetupMacros(t *testing.T) {
	// Setup minimal configuration
	Configuration = &Config{
		PrivateIPv4: "192.168.1.1",
		PrivateIPv6: "fe80::1",
		PublicIPv4:  "8.8.8.8",
		PublicIPv6:  "2001:4860:4860::8888",
		PublicServer: &PublicServer{
			Zone: entities.Zone{
				Name: "example.com.",
			},
		},
		InternalServer: &InternalServer{
			Zone: entities.Zone{
				Name: "internal.local.",
			},
		},
	}

	setupMacros()

	assert.Equal(t, "192.168.1.1", macros["PRIVATE_IPv4"])
	assert.Equal(t, "fe80::1", macros["PRIVATE_IPv6"])
	assert.Equal(t, "8.8.8.8", macros["PUBLIC_IPv4"])
	assert.Equal(t, "2001:4860:4860::8888", macros["PUBLIC_IPv6"])
	assert.Equal(t, "example.com.", macros["PUBLIC_DOMAIN"])
	assert.Equal(t, "internal.local.", macros["PRIVATE_DOMAIN"])
	assert.NotEmpty(t, macros["HOSTNAME"])
	assert.NotEmpty(t, macros["PREFERRED_IP"])
}

func TestSetupMacros_HostnamePanic(t *testing.T) {
	// This test can't easily force os.Hostname() to fail, but we document the behavior
	// The setupMacros function will panic if hostname cannot be retrieved
	hostname, err := os.Hostname()
	assert.NoError(t, err, "System should be able to get hostname")
	assert.NotEmpty(t, hostname)
}

func TestExpand(t *testing.T) {
	// Setup macros
	macros["HOSTNAME"] = "testhost"
	macros["PUBLIC_IPv4"] = "1.2.3.4"
	macros["LOCAL_IPv4"] = "192.168.1.100"

	zone := &entities.Zone{
		Name: "test.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "${HOSTNAME}", Value: "${PUBLIC_IPv4}", TTL: 3600},
				{Name: "www", Value: "${PUBLIC_IPv4}", TTL: 3600},
			},
			AAAARecords: []*entities.AAAARecord{
				{Name: "${HOSTNAME}", Value: "${PUBLIC_IPv6}", TTL: 3600},
			},
			CNAMERecords: []*entities.CNAMERecord{
				{Name: "${HOSTNAME}-alias", Value: "${HOSTNAME}.test.com.", TTL: 3600},
			},
			MXRecords: []*entities.MXRecord{
				{Name: "test.com.", Value: "mail.${HOSTNAME}.test.com.", Priority: 10, TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: "test.com.", Value: "ns.${HOSTNAME}.test.com.", TTL: 3600},
			},
			SRVRecords: []*entities.SRVRecord{
				{Name: "_http._tcp", Target: "${HOSTNAME}.test.com.", Port: 80, TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: "${HOSTNAME}", Value: "host=${HOSTNAME}", TTL: 3600},
			},
		},
	}

	err := Expand(zone)
	assert.NoError(t, err)

	// Verify A records expanded
	assert.Equal(t, "testhost", zone.RecordSet.ARecords[0].Name)
	assert.Equal(t, "1.2.3.4", zone.RecordSet.ARecords[0].Value)
	assert.Equal(t, "www", zone.RecordSet.ARecords[1].Name)
	assert.Equal(t, "1.2.3.4", zone.RecordSet.ARecords[1].Value)

	// Verify AAAA records expanded
	assert.Equal(t, "testhost", zone.RecordSet.AAAARecords[0].Name)

	// Verify CNAME records expanded
	assert.Equal(t, "testhost-alias", zone.RecordSet.CNAMERecords[0].Name)
	assert.Equal(t, "testhost.test.com.", zone.RecordSet.CNAMERecords[0].Value)

	// Verify MX records expanded
	assert.Equal(t, "mail.testhost.test.com.", zone.RecordSet.MXRecords[0].Value)

	// Verify NS records expanded
	assert.Equal(t, "ns.testhost.test.com.", zone.RecordSet.NSRecords[0].Value)

	// Verify SRV records expanded
	assert.Equal(t, "testhost.test.com.", zone.RecordSet.SRVRecords[0].Target)

	// Verify TXT records expanded
	assert.Equal(t, "testhost", zone.RecordSet.TXTRecords[0].Name)
	assert.Equal(t, "host=testhost", zone.RecordSet.TXTRecords[0].Value)
}

func TestExpand_EmptyZone(t *testing.T) {
	zone := &entities.Zone{
		Name:      "empty.com.",
		RecordSet: entities.RecordSet{},
	}

	err := Expand(zone)
	assert.NoError(t, err)
}

// TestSetupMacros_NilPublicServer verifies setupMacros with nil PublicServer.
func TestSetupMacros_NilPublicServer(t *testing.T) {
	// Clear PUBLIC_DOMAIN before test since setupMacros doesn't clear it
	macros["PUBLIC_DOMAIN"] = ""

	Configuration = &Config{
		PrivateIPv4:  "192.168.1.1",
		PrivateIPv6:  "fe80::1",
		PublicIPv4:   "8.8.8.8",
		PublicIPv6:   "2001:4860:4860::8888",
		PublicServer: nil, // Explicitly nil
		InternalServer: &InternalServer{
			Zone: entities.Zone{
				Name: "internal.local.",
			},
		},
	}

	setupMacros()

	assert.Equal(t, "192.168.1.1", macros["PRIVATE_IPv4"])
	assert.Equal(t, "internal.local.", macros["PRIVATE_DOMAIN"])
	assert.Empty(t, macros["PUBLIC_DOMAIN"]) // Remains empty since PublicServer is nil
}

// TestSetupMacros_NilInternalServer verifies setupMacros with nil InternalServer.
func TestSetupMacros_NilInternalServer(t *testing.T) {
	// Clear PRIVATE_DOMAIN before test since setupMacros doesn't clear it
	macros["PRIVATE_DOMAIN"] = ""

	Configuration = &Config{
		PrivateIPv4: "192.168.1.1",
		PrivateIPv6: "fe80::1",
		PublicIPv4:  "8.8.8.8",
		PublicIPv6:  "2001:4860:4860::8888",
		PublicServer: &PublicServer{
			Zone: entities.Zone{
				Name: "example.com.",
			},
		},
		InternalServer: nil, // Explicitly nil
	}

	setupMacros()

	assert.Equal(t, "8.8.8.8", macros["PUBLIC_IPv4"])
	assert.Equal(t, "example.com.", macros["PUBLIC_DOMAIN"])
	assert.Empty(t, macros["PRIVATE_DOMAIN"]) // Remains empty since InternalServer is nil
}

// TestSetupMacros_BothServersNil verifies setupMacros with both servers nil.
func TestSetupMacros_BothServersNil(t *testing.T) {
	// Clear domain macros before test since setupMacros doesn't clear them
	macros["PUBLIC_DOMAIN"] = ""
	macros["PRIVATE_DOMAIN"] = ""

	Configuration = &Config{
		PrivateIPv4:    "192.168.1.1",
		PrivateIPv6:    "fe80::1",
		PublicIPv4:     "8.8.8.8",
		PublicIPv6:     "2001:4860:4860::8888",
		PublicServer:   nil,
		InternalServer: nil,
	}

	setupMacros()

	assert.Equal(t, "192.168.1.1", macros["PRIVATE_IPv4"])
	assert.Equal(t, "8.8.8.8", macros["PUBLIC_IPv4"])
	assert.Empty(t, macros["PUBLIC_DOMAIN"])
	assert.Empty(t, macros["PRIVATE_DOMAIN"])
}

// TestExpandVar_NoMacroInString verifies ExpandVar with no macro syntax.
func TestExpandVar_NoMacroInString(t *testing.T) {
	result := ExpandVar("just-a-plain-string")
	assert.Equal(t, "just-a-plain-string", result)
}

// TestExpandVar_EmptyString verifies ExpandVar with empty string.
func TestExpandVar_EmptyString(t *testing.T) {
	result := ExpandVar("")
	assert.Equal(t, "", result)
}

// TestExpandVar_MalformedMacro verifies ExpandVar with malformed macro syntax.
func TestExpandVar_MalformedMacro(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"unclosed brace", "${UNCLOSED", "${UNCLOSED"},
		{"no dollar sign", "{TEST_VAR}", "{TEST_VAR}"},
		{"only dollar", "$TEST_VAR", "$TEST_VAR"},
		// Note: ${} doesn't match regex \$\{([^}]+)\} because [^}]+ requires at least one char
		{"empty braces", "${}", "${}"},
		{"mixed valid and invalid", "${PUBLIC_IPv4}${UNCLOSED", "8.8.8.8${UNCLOSED"},
	}

	// Setup macro for test
	macros["PUBLIC_IPv4"] = "8.8.8.8"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandVar(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExpand_NilRecordSlices verifies Expand with nil record slices.
func TestExpand_NilRecordSlices(t *testing.T) {
	zone := &entities.Zone{
		Name: "nil-records.com.",
		RecordSet: entities.RecordSet{
			ARecords:     nil,
			AAAARecords:  nil,
			CNAMERecords: nil,
			MXRecords:    nil,
			NSRecords:    nil,
			SRVRecords:   nil,
			TXTRecords:   nil,
		},
	}

	err := Expand(zone)
	assert.NoError(t, err)
}

// TestExpandVar_MultipleOccurrences verifies expanding same macro multiple times.
func TestExpandVar_MultipleOccurrences(t *testing.T) {
	macros["HOST"] = "server1"

	input := "${HOST}.example.com has address ${HOST}.local"
	expected := "server1.example.com has address server1.local"

	result := ExpandVar(input)
	assert.Equal(t, expected, result)
}

// TestErrMacroNotFound verifies the error constant.
func TestErrMacroNotFound(t *testing.T) {
	assert.NotNil(t, ErrMacroNotFound)
	assert.Equal(t, "dns: macro not found", ErrMacroNotFound.Error())
}
