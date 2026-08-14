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

package tpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// noCtxFlags returns CommonFlags with nil GetContext, causing
// cli.NewBaseCommand to return ErrNoContextSet{}.
func noCtxFlags() *cli.CommonFlags {
	return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
}

// assertNoCtxErr verifies the error is cli.ErrNoContextSet.
func assertNoCtxErr(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.IsType(t, cli.ErrNoContextSet{}, err)
}

// =============================================================================
// Clear
// =============================================================================

func TestRunClear_NoContext(t *testing.T) {
	err := runClear(noCtxFlags(), "password")
	assertNoCtxErr(t, err)
}

// =============================================================================
// EK
// =============================================================================

func TestRunEKCreate_NoContext(t *testing.T) {
	err := runEKCreate(noCtxFlags(), "RSA", true)
	assertNoCtxErr(t, err)
}

func TestRunEKInfo_NoContext(t *testing.T) {
	err := runEKInfo(noCtxFlags(), 0x81010001)
	assertNoCtxErr(t, err)
}

func TestRunEKCertificate_NoContext(t *testing.T) {
	err := runEKCertificate(noCtxFlags())
	assertNoCtxErr(t, err)
}

func TestRunEKDelete_NoContext(t *testing.T) {
	err := runEKDelete(noCtxFlags(), 0x81010001, "pass")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Info
// =============================================================================

func TestRunInfo_NoContext(t *testing.T) {
	err := runInfo(noCtxFlags())
	assertNoCtxErr(t, err)
}

// =============================================================================
// Eventlog
// =============================================================================

func TestRunEventlog_NoContext(t *testing.T) {
	err := runEventlog(noCtxFlags(), "text")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Flush
// =============================================================================

func TestRunFlush_NoContext(t *testing.T) {
	err := runFlush(noCtxFlags())
	assertNoCtxErr(t, err)
}

// =============================================================================
// DeviceAttributes
// =============================================================================

func TestRunDeviceAttributes_NoContext(t *testing.T) {
	err := runDeviceAttributes(noCtxFlags())
	assertNoCtxErr(t, err)
}

// =============================================================================
// IAK
// =============================================================================

func TestRunIAKGenerate_NoContext(t *testing.T) {
	err := runIAKGenerate(noCtxFlags(), "ECDSA", false)
	assertNoCtxErr(t, err)
}

func TestRunIAKInfo_NoContext(t *testing.T) {
	err := runIAKInfo(noCtxFlags())
	assertNoCtxErr(t, err)
}

func TestRunIAKDelete_NoContext(t *testing.T) {
	err := runIAKDelete(noCtxFlags())
	assertNoCtxErr(t, err)
}

func TestRunIAKCSR_NoContext(t *testing.T) {
	err := runIAKCSR(noCtxFlags(), "test-cn", "test-org", "US", "CA", "LA", "Engineering")
	assertNoCtxErr(t, err)
}

func TestRunIAKInstall_NoContext(t *testing.T) {
	err := runIAKInstall(noCtxFlags(), "/tmp/nonexistent.pem")
	assertNoCtxErr(t, err)
}

func TestRunIAKCert_NoContext(t *testing.T) {
	err := runIAKCert(noCtxFlags())
	assertNoCtxErr(t, err)
}

// =============================================================================
// IDevID
// =============================================================================

func TestRunIDevIDGenerate_NoContext(t *testing.T) {
	err := runIDevIDGenerate(noCtxFlags(), "Ed25519", true)
	assertNoCtxErr(t, err)
}

func TestRunIDevIDInfo_NoContext(t *testing.T) {
	err := runIDevIDInfo(noCtxFlags())
	assertNoCtxErr(t, err)
}

func TestRunIDevIDDelete_NoContext(t *testing.T) {
	err := runIDevIDDelete(noCtxFlags())
	assertNoCtxErr(t, err)
}

func TestRunIDevIDCSR_NoContext(t *testing.T) {
	err := runIDevIDCSR(noCtxFlags(), "cn", "org", "US", "CA", "LA", "OU")
	assertNoCtxErr(t, err)
}

func TestRunIDevIDInstall_NoContext(t *testing.T) {
	err := runIDevIDInstall(noCtxFlags(), "/tmp/nonexistent.pem")
	assertNoCtxErr(t, err)
}

func TestRunIDevIDCert_NoContext(t *testing.T) {
	err := runIDevIDCert(noCtxFlags())
	assertNoCtxErr(t, err)
}

// =============================================================================
// NVRAM
// =============================================================================

func TestRunNVRAMDefine_NoContext(t *testing.T) {
	err := runNVRAMDefine(noCtxFlags(), &nvramDefineOptions{
		Index:    0x01500001,
		Size:     32,
		Password: "test",
	})
	assertNoCtxErr(t, err)
}

func TestRunNVRAMWrite_NoContext(t *testing.T) {
	err := runNVRAMWrite(noCtxFlags(), &nvramWriteOptions{
		Index:    0x01500001,
		Data:     "hello",
		Password: "test",
	})
	assertNoCtxErr(t, err)
}

func TestRunNVRAMRead_NoContext(t *testing.T) {
	err := runNVRAMRead(noCtxFlags(), &nvramReadOptions{
		Index: 0x01500001,
		Size:  32,
	})
	assertNoCtxErr(t, err)
}

func TestRunNVRAMDelete_NoContext(t *testing.T) {
	err := runNVRAMDelete(noCtxFlags(), 0x01500001, "pass")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Provision
// =============================================================================

func TestRunProvision_NoContext(t *testing.T) {
	err := runProvision(noCtxFlags(), &provisionOptions{
		OwnerPassword: "test",
	})
	assertNoCtxErr(t, err)
}

// =============================================================================
// Seal / Unseal
// =============================================================================

func TestRunSeal_NoContext(t *testing.T) {
	err := runSeal(noCtxFlags(), &sealOptions{
		Data:     "secret",
		Password: "pass",
	})
	assertNoCtxErr(t, err)
}

func TestRunUnseal_NoContext(t *testing.T) {
	err := runUnseal(noCtxFlags(), &unsealOptions{
		CN:       "test",
		Password: "pass",
	})
	assertNoCtxErr(t, err)
}

// =============================================================================
// SRK
// =============================================================================

func TestRunSRKCreate_NoContext(t *testing.T) {
	err := runSRKCreate(noCtxFlags(), &srkCreateOptions{
		Algorithm: "RSA",
	})
	assertNoCtxErr(t, err)
}

func TestRunSRKInfo_NoContext(t *testing.T) {
	err := runSRKInfo(noCtxFlags(), 0x81000001)
	assertNoCtxErr(t, err)
}

func TestRunSRKDelete_NoContext(t *testing.T) {
	err := runSRKDelete(noCtxFlags(), 0x81000001, "pass")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Command construction — cover RunE paths for partial-coverage commands
// =============================================================================

func TestNewInfoCommand_RunE_NoContext(t *testing.T) {
	cmd := newInfoCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewEventlogCommand_RunE_NoContext(t *testing.T) {
	cmd := newEventlogCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewEKCreateCommand_RunE_NoContext(t *testing.T) {
	cmd := newEKCreateCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewEKInfoCommand_RunE_NoContext(t *testing.T) {
	cmd := newEKInfoCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewEKCertificateCommand_RunE_NoContext(t *testing.T) {
	cmd := newEKCertificateCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewEKDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newEKDeleteCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIAKGenerateCommand_RunE_NoContext(t *testing.T) {
	cmd := newIAKGenerateCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIAKInfoCommand_RunE_NoContext(t *testing.T) {
	cmd := newIAKInfoCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIAKDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newIAKDeleteCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIAKCSRCommand_RunE_NoContext(t *testing.T) {
	cmd := newIAKCSRCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIAKInstallCommand_RunE_NoContext(t *testing.T) {
	cmd := newIAKInstallCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIAKCertCommand_RunE_NoContext(t *testing.T) {
	cmd := newIAKCertCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIDevIDGenerateCommand_RunE_NoContext(t *testing.T) {
	cmd := newIDevIDGenerateCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIDevIDInfoCommand_RunE_NoContext(t *testing.T) {
	cmd := newIDevIDInfoCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIDevIDDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newIDevIDDeleteCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIDevIDCSRCommand_RunE_NoContext(t *testing.T) {
	cmd := newIDevIDCSRCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIDevIDInstallCommand_RunE_NoContext(t *testing.T) {
	cmd := newIDevIDInstallCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewIDevIDCertCommand_RunE_NoContext(t *testing.T) {
	cmd := newIDevIDCertCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewNVRAMDefineCommand_RunE_NoContext(t *testing.T) {
	cmd := newNVRAMDefineCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewNVRAMWriteCommand_RunE_NoContext(t *testing.T) {
	cmd := newNVRAMWriteCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewNVRAMReadCommand_RunE_NoContext(t *testing.T) {
	cmd := newNVRAMReadCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewNVRAMDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newNVRAMDeleteCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewProvisionCommand_RunE_NoContext(t *testing.T) {
	cmd := newProvisionCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewSealCommand_RunE_NoContext(t *testing.T) {
	cmd := newSealCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}

func TestNewUnsealCommand_RunE_NoContext(t *testing.T) {
	cmd := newUnsealCommand(noCtxFlags)
	err := cmd.RunE(cmd, nil)
	assertNoCtxErr(t, err)
}
