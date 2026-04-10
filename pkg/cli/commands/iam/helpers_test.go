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

package iam

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFormatTimestamp(t *testing.T) {
	t.Run("nil timestamp", func(t *testing.T) {
		result := formatTimestamp(nil)
		assert.Equal(t, "N/A", result)
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
		result := formatTimestamp(ts)
		assert.Equal(t, "2025-06-15T12:00:00Z", result)
	})
}

func TestFormatTimestampProto(t *testing.T) {
	t.Run("nil delegates to formatTimestamp", func(t *testing.T) {
		result := formatTimestampProto(nil)
		assert.Equal(t, "N/A", result)
	})

	t.Run("valid delegates to formatTimestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
		result := formatTimestampProto(ts)
		assert.Equal(t, "2024-01-01T00:00:00Z", result)
	})
}

func TestFormatBool(t *testing.T) {
	assert.Equal(t, "Yes", formatBool(true))
	assert.Equal(t, "No", formatBool(false))
}

func TestFormatStringSlice(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := formatStringSlice(nil)
		assert.Equal(t, "none", result)
	})

	t.Run("empty slice literal", func(t *testing.T) {
		result := formatStringSlice([]string{})
		assert.Equal(t, "none", result)
	})

	t.Run("single item", func(t *testing.T) {
		result := formatStringSlice([]string{"admin"})
		assert.Equal(t, "admin", result)
	})

	t.Run("multiple items", func(t *testing.T) {
		result := formatStringSlice([]string{"admin", "user", "viewer"})
		assert.Equal(t, "admin, user, viewer", result)
	})
}

func TestFormatAttributes(t *testing.T) {
	t.Run("nil map", func(t *testing.T) {
		result := formatAttributes(nil)
		assert.Equal(t, "none", result)
	})

	t.Run("empty map", func(t *testing.T) {
		result := formatAttributes(map[string]string{})
		assert.Equal(t, "none", result)
	})

	t.Run("single entry", func(t *testing.T) {
		result := formatAttributes(map[string]string{"env": "prod"})
		assert.Contains(t, result, "env=prod")
	})

	t.Run("multiple entries", func(t *testing.T) {
		result := formatAttributes(map[string]string{"env": "prod", "region": "us-west"})
		assert.Contains(t, result, "env=prod")
		assert.Contains(t, result, "region=us-west")
	})
}

func TestParseStringSlice(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result := parseStringSlice("")
		assert.Nil(t, result)
	})

	t.Run("single item", func(t *testing.T) {
		result := parseStringSlice("admin")
		assert.Equal(t, []string{"admin"}, result)
	})

	t.Run("multiple items", func(t *testing.T) {
		result := parseStringSlice("admin,user,viewer")
		assert.Equal(t, []string{"admin", "user", "viewer"}, result)
	})

	t.Run("items with spaces", func(t *testing.T) {
		result := parseStringSlice("admin , user , viewer")
		assert.Equal(t, []string{"admin", "user", "viewer"}, result)
	})

	t.Run("trailing comma", func(t *testing.T) {
		result := parseStringSlice("admin,user,")
		assert.Equal(t, []string{"admin", "user"}, result)
	})

	t.Run("empty items filtered", func(t *testing.T) {
		result := parseStringSlice("admin,,user")
		assert.Equal(t, []string{"admin", "user"}, result)
	})
}

func TestParseAttributes(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result := parseAttributes("")
		assert.Nil(t, result)
	})

	t.Run("single pair", func(t *testing.T) {
		result := parseAttributes("env=prod")
		assert.Equal(t, map[string]string{"env": "prod"}, result)
	})

	t.Run("multiple pairs", func(t *testing.T) {
		result := parseAttributes("env=prod,region=us-west")
		assert.Equal(t, map[string]string{"env": "prod", "region": "us-west"}, result)
	})

	t.Run("with spaces", func(t *testing.T) {
		result := parseAttributes(" env = prod , region = us-west ")
		assert.Equal(t, map[string]string{"env": "prod", "region": "us-west"}, result)
	})

	t.Run("value with equals sign", func(t *testing.T) {
		result := parseAttributes("expr=a=b")
		assert.Equal(t, map[string]string{"expr": "a=b"}, result)
	})

	t.Run("entry without equals is skipped", func(t *testing.T) {
		result := parseAttributes("env=prod,badentry")
		assert.Equal(t, map[string]string{"env": "prod"}, result)
	})

	t.Run("empty entries filtered", func(t *testing.T) {
		result := parseAttributes("env=prod,,region=us-west")
		assert.Equal(t, map[string]string{"env": "prod", "region": "us-west"}, result)
	})
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 8, "hello..."},
		{"maxLen 3 no ellipsis", "hello", 3, "hel"},
		{"maxLen 2 no ellipsis", "hello", 2, "he"},
		{"maxLen 1 no ellipsis", "hello", 1, "h"},
		{"empty string", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}
