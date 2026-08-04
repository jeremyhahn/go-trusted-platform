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

package tpmnv

import (
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

func TestBuildAttributes_Defaults(t *testing.T) {
	a := BuildAttributes(nil)
	assert.True(t, a.AuthRead, "default AuthRead")
	assert.True(t, a.AuthWrite, "default AuthWrite")
	assert.True(t, a.NoDA, "default NoDA (must not lock out DA hierarchy)")
	assert.Equal(t, tpmgo.TPMNTOrdinary, a.NT)
}

func TestBuildAttributes_NamedFlags(t *testing.T) {
	a := BuildAttributes([]string{
		"AUTHREAD", "AUTHWRITE", "OWNERREAD", "OWNERWRITE",
		"PPREAD", "PPWRITE", "WRITELOCK", "READLOCK",
		"WRITTEN", "WRITEALL", "GLOBALLOCK", "POLICYREAD", "POLICYWRITE",
	})
	assert.True(t, a.AuthRead)
	assert.True(t, a.AuthWrite)
	assert.True(t, a.OwnerRead)
	assert.True(t, a.OwnerWrite)
	assert.True(t, a.PPRead)
	assert.True(t, a.PPWrite)
	assert.True(t, a.WriteDefine)
	assert.True(t, a.ReadSTClear)
	assert.True(t, a.Written)
	assert.True(t, a.WriteAll)
	assert.True(t, a.GlobalLock)
	assert.True(t, a.PolicyRead)
	assert.True(t, a.PolicyWrite)
	// A non-empty list defaults NoDA to true unless "DA" is present.
	assert.True(t, a.NoDA)
}

func TestBuildAttributes_DAOverride(t *testing.T) {
	a := BuildAttributes([]string{"AUTHREAD", "DA"})
	assert.True(t, a.AuthRead)
	assert.False(t, a.NoDA, "explicit DA must clear NoDA")

	b := BuildAttributes([]string{"AUTHREAD", "NO_DA"})
	assert.True(t, b.NoDA)
}

func TestBuildAttributes_UnknownIgnored(t *testing.T) {
	a := BuildAttributes([]string{"BOGUS", "AUTHREAD"})
	assert.True(t, a.AuthRead)
	assert.False(t, a.AuthWrite, "unknown names must not set unrelated flags")
}
