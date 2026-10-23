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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateEmail_Accepts(t *testing.T) {
	for _, email := range []string{
		"admin@example.com",
		"first.last+tag@sub.example.co",
		"a_b-c%d@host-name.io",
	} {
		t.Run(email, func(t *testing.T) {
			assert.NoError(t, ValidateEmail(email))
		})
	}
}

func TestValidateEmail_Rejects(t *testing.T) {
	for _, email := range []string{
		"",
		"jhahn",
		"jhahn@localhost",
		"a@b.c",
		"@example.com",
		"j hahn@example.com",
		"jhahn@example.com\n",
	} {
		t.Run(email, func(t *testing.T) {
			err := ValidateEmail(email)
			var invalid ErrInvalidEmail
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, email, invalid.Email)
			assert.Contains(t, err.Error(), "invalid email address")
		})
	}
}
