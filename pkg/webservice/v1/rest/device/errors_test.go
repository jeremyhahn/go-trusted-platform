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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMissingRole(t *testing.T) {
	err := ErrMissingRole{}
	assert.Equal(t, "device: role is required", err.Error())
	assert.True(t, errors.As(err, &ErrMissingRole{}))
}

func TestErrMissingTemplate(t *testing.T) {
	err := ErrMissingTemplate{}
	assert.Equal(t, "device: template payload is required", err.Error())
}

func TestErrInvalidRequestBody(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidRequestBody{Reason: "unexpected EOF"}
		assert.Equal(t, "device: invalid request body: unexpected EOF", err.Error())
	})
	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidRequestBody{}
		assert.Equal(t, "device: invalid request body", err.Error())
	})
}

func TestErrInvalidTemplateID(t *testing.T) {
	err := ErrInvalidTemplateID{}
	assert.Equal(t, "device: invalid template id", err.Error())
}

func TestErrTemplateSaveFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("disk full")
		err := ErrTemplateSaveFailed{Cause: cause}
		assert.Equal(t, "device: failed to save template: disk full", err.Error())
	})
	t.Run("without cause", func(t *testing.T) {
		err := ErrTemplateSaveFailed{}
		assert.Equal(t, "device: failed to save template", err.Error())
	})
}

func TestErrProfileCreateFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("not found")
		err := ErrProfileCreateFailed{Cause: cause}
		assert.Equal(t, "device: failed to create profile: not found", err.Error())
	})
	t.Run("without cause", func(t *testing.T) {
		err := ErrProfileCreateFailed{}
		assert.Equal(t, "device: failed to create profile", err.Error())
	})
}

func TestErrProfileSaveFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("constraint violation")
		err := ErrProfileSaveFailed{Cause: cause}
		assert.Equal(t, "device: failed to save profile: constraint violation", err.Error())
	})
	t.Run("without cause", func(t *testing.T) {
		err := ErrProfileSaveFailed{}
		assert.Equal(t, "device: failed to save profile", err.Error())
	})
}

func TestErrTemplateServiceNil(t *testing.T) {
	err := ErrTemplateServiceNil{}
	assert.Equal(t, "device: template service not initialized", err.Error())
}

func TestErrProfileServiceNil(t *testing.T) {
	err := ErrProfileServiceNil{}
	assert.Equal(t, "device: profile service not initialized", err.Error())
}

func TestErrMissingHostname(t *testing.T) {
	err := ErrMissingHostname{}
	assert.Equal(t, "device: hostname is required", err.Error())
}
