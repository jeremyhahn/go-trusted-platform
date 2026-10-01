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

package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirmwareOverrides(t *testing.T) {
	f := firmwareOverrides{}
	fs := flag.NewFlagSet("pxeboot", flag.ContinueOnError)
	fs.Var(f, "firmware-override", "")
	require.NoError(t, fs.Parse([]string{
		"--firmware-override", "snponly-aarch64.efi=/data/firmware/snponly-aarch64.efi",
		"--firmware-override", "ipxe.efi=/data/firmware/ipxe.efi",
	}))
	assert.Equal(t, firmwareOverrides{"snponly-aarch64.efi": "/data/firmware/snponly-aarch64.efi", "ipxe.efi": "/data/firmware/ipxe.efi"}, f)
	assert.Equal(t, "ipxe.efi=/data/firmware/ipxe.efi,snponly-aarch64.efi=/data/firmware/snponly-aarch64.efi", f.String(), "sorted")

	for _, bad := range []string{"no-equals", "=path", "name=", "ipxe.efi=/again"} {
		assert.Error(t, f.Set(bad), bad)
	}
}

func TestValidateRequiredFlags(t *testing.T) {
	require.NoError(t, validateRequiredFlags("m", "/data/media", "1.1.1.1", "1.1.1.2", "1.1.1.3"))
	err := validateRequiredFlags("", "", "1.1.1.1", "", "1.1.1.3")
	var msg *MessageError
	require.ErrorAs(t, err, &msg)
	assert.Equal(t, "required flags not set: --dhcp-range-start, --manifest, --media-dir", msg.Error(), "every missing flag, in a stable order")
}
