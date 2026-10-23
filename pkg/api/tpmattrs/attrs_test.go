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

package tpmattrs

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

var errRefused = errors.New("TPM_RC_VALUE")

type fakeTPM struct {
	algorithms, commands, curves []string
	algErr, cmdErr, curveErr     error

	device                string
	fips, pcrExtended     bool
	fipsErr, pcrErr       error
	canSeal               bool
	cfg                   *xkmssdk.TPMConfig
	props                 *xkmssdk.PropertiesFixed
	propsErr              error
	ek, srk, iak          *xkmssdk.KeyAttributes
	ekErr, srkErr, iakErr error

	banks       []xkmssdk.PCRBank
	banksErr    error
	readPCRList []uint
}

func (f *fakeTPM) SupportedAlgorithms() ([]string, error) { return f.algorithms, f.algErr }
func (f *fakeTPM) SupportedCommands() ([]string, error)   { return f.commands, f.cmdErr }
func (f *fakeTPM) SupportedECCCurves() ([]string, error)  { return f.curves, f.curveErr }
func (f *fakeTPM) Device() string                         { return f.device }
func (f *fakeTPM) IsFIPS140_2() (bool, error)             { return f.fips, f.fipsErr }
func (f *fakeTPM) IsPlatformPCRExtended() (bool, error)   { return f.pcrExtended, f.pcrErr }
func (f *fakeTPM) CanSeal() bool                          { return f.canSeal }
func (f *fakeTPM) Config() *xkmssdk.TPMConfig             { return f.cfg }
func (f *fakeTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return f.props, f.propsErr
}
func (f *fakeTPM) EKAttributes() (*xkmssdk.KeyAttributes, error)   { return f.ek, f.ekErr }
func (f *fakeTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) { return f.srk, f.srkErr }
func (f *fakeTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error)  { return f.iak, f.iakErr }

func keyAttrs(handle uint32, alg x509.PublicKeyAlgorithm) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm:  alg,
		TPMAttributes: &xkmssdk.TPMAttributes{Handle: xkmssdk.TPMHandle(handle)},
	}
}

func TestReadCapabilities_ReturnsTheThreeLists(t *testing.T) {
	tpm := &fakeTPM{
		algorithms: []string{"rsa", "ecc"},
		commands:   []string{"TPM2_Quote"},
		curves:     []string{"NIST_P256"},
	}

	got, err := ReadCapabilities(tpm)

	require.NoError(t, err)
	assert.Equal(t, Capabilities{
		Algorithms: []string{"rsa", "ecc"},
		Commands:   []string{"TPM2_Quote"},
		ECCCurves:  []string{"NIST_P256"},
	}, got)
}

func TestReadCapabilities_NamesTheRefusedList(t *testing.T) {
	cases := []struct {
		name string
		tpm  *fakeTPM
		list string
	}{
		{"algorithms", &fakeTPM{algErr: errRefused}, ListAlgorithms},
		{"commands", &fakeTPM{cmdErr: errRefused}, ListCommands},
		{"curves", &fakeTPM{curveErr: errRefused}, ListECCCurves},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadCapabilities(tc.tpm)

			var readErr ErrCapabilityRead
			require.ErrorAs(t, err, &readErr)
			assert.Equal(t, tc.list, readErr.List)
			assert.ErrorIs(t, err, errRefused)
			assert.Contains(t, err.Error(), tc.list)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Equal(t, Capabilities{}, got)
		})
	}
}

func TestReadPlatform_ReportsEveryAttribute(t *testing.T) {
	tpm := &fakeTPM{
		device:      "/dev/tpmrm0",
		fips:        true,
		pcrExtended: true,
		canSeal:     true,
		cfg:         &xkmssdk.TPMConfig{UseSimulator: true},
		props:       &xkmssdk.PropertiesFixed{Manufacturer: "IFX"},
		ek:          keyAttrs(0x81010001, x509.RSA),
		srk:         keyAttrs(0x81000001, x509.RSA),
		iak:         keyAttrs(0x81010002, x509.ECDSA),
	}

	got := ReadPlatform(tpm)

	assert.Equal(t, Platform{
		Device:       "/dev/tpmrm0",
		IsFIPS:       true,
		PCRExtended:  true,
		CanSeal:      true,
		IsSimulator:  true,
		Manufacturer: "IFX",
		EK:           &KeyRef{Handle: 0x81010001, Algorithm: "RSA"},
		SRK:          &KeyRef{Handle: 0x81000001, Algorithm: "RSA"},
		IAK:          &KeyRef{Handle: 0x81010002, Algorithm: "ECDSA"},
	}, got)
}

func TestReadPlatform_LeavesWhatTheTPMCannotReportEmpty(t *testing.T) {
	tpm := &fakeTPM{
		device:   "/dev/tpmrm0",
		fips:     true,
		fipsErr:  errRefused,
		pcrErr:   errRefused,
		propsErr: errRefused,
		ekErr:    errRefused,
		srk:      &xkmssdk.KeyAttributes{},
	}

	got := ReadPlatform(tpm)

	assert.Equal(t, Platform{Device: "/dev/tpmrm0"}, got,
		"a refused read is false or empty, never the value returned beside the error")
}

func (f *fakeTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	f.readPCRList = pcrList
	return f.banks, f.banksErr
}

func TestActivePCRBanks_NamesEachAllocatedBankOnce(t *testing.T) {
	tpm := &fakeTPM{banks: []xkmssdk.PCRBank{
		{Algorithm: "SHA1"},
		{Algorithm: "SHA256"},
		{Algorithm: "sha256"},
		{Algorithm: ""},
		{Algorithm: "SHA384"},
	}}

	got := ActivePCRBanks(tpm)

	assert.Equal(t, []string{"sha1", "sha256", "sha384"}, got,
		"lower-case, in TPM order, without duplicates or unnamed banks")
	assert.Equal(t, []uint{0}, tpm.readPCRList, "PCR 0 is held by every allocated bank")
}

func TestActivePCRBanks_RefusedReadReportsNoBanks(t *testing.T) {
	tpm := &fakeTPM{banks: []xkmssdk.PCRBank{{Algorithm: "SHA256"}}, banksErr: errRefused}

	assert.Empty(t, ActivePCRBanks(tpm),
		"a refused read reports no banks, never the banks returned beside the error")
}
