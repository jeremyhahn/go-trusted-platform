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

package daemon

import (
	"context"
	"errors"
	"math"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv/tpmnvtest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmpcr"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const testNVIndex = 0x01500001

var (
	errPropertiesFailed = errors.New("get capability failed")
	errExtendFailed     = errors.New("pcr extend failed")
)

// nvPCRTPM is an xkmssdk.TrustedPlatformModule whose NV commands run
// against the tpmnvtest in-memory transport and whose PCR extends are
// recorded. Methods it does not override panic through the nil embed.
type nvPCRTPM struct {
	xkmssdk.TrustedPlatformModule
	nv        *tpmnvtest.TPM
	props     *xkmssdk.PropertiesFixed
	propsErr  error
	extendErr error
	extends   []tpmExtend
}

// tpmExtend is one recorded ExtendPCR call.
type tpmExtend struct {
	index   int
	hashAlg string
	data    []byte
}

func (t *nvPCRTPM) Transport() transport.TPM {
	if t.nv == nil {
		return nil
	}
	return t.nv
}

func (t *nvPCRTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return t.props, t.propsErr
}

func (t *nvPCRTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	t.extends = append(t.extends, tpmExtend{index: pcrIndex, hashAlg: hashAlg, data: data})
	return t.extendErr
}

// newNVTPM returns a TPM holding one 16-byte index authorized by "pw" and
// an owner hierarchy authorized by "owner".
func newNVTPM() *nvPCRTPM {
	nv := tpmnvtest.New()
	nv.OwnerAuth = []byte("owner")
	nv.Define(testNVIndex, 16, tpmgo.TPMANV{AuthRead: true, AuthWrite: true, NoDA: true}, []byte("pw"))
	return &nvPCRTPM{nv: nv}
}

func newMCPProviderWithTPM(tpm xkmssdk.TrustedPlatformModule) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{TPM2Service: tpm})
}

func TestMCPServiceProvider_TPMExtendPCR(t *testing.T) {
	tpm := &nvPCRTPM{}
	p := newMCPProviderWithTPM(tpm)

	result, err := p.TPMExtendPCR(context.Background(), 16, "", []byte("measurement"))

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"success": true, "message": "PCR 16 extended"}, result)
	assert.Equal(t, []tpmExtend{{index: 16, hashAlg: tpmpcr.DefaultHashAlg, data: []byte("measurement")}}, tpm.extends)
}

func TestMCPServiceProvider_TPMExtendPCR_Errors(t *testing.T) {
	tests := []struct {
		name  string
		tpm   *nvPCRTPM
		index int
		data  []byte
		want  error
	}{
		{"index past 23", &nvPCRTPM{}, 24, []byte("x"), tpmpcr.ErrInvalidIndex{Index: 24}},
		{"no data", &nvPCRTPM{}, 16, nil, tpmpcr.ErrDataRequired{}},
		{"TPM failure", &nvPCRTPM{extendErr: errExtendFailed}, 16, []byte("x"), errExtendFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newMCPProviderWithTPM(tt.tpm).TPMExtendPCR(context.Background(), tt.index, "", tt.data)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestMCPServiceProvider_TPMNVList(t *testing.T) {
	tpm := &nvPCRTPM{props: &xkmssdk.PropertiesFixed{NVIndexes: []xkmssdk.NVIndexInfo{
		{Handle: testNVIndex, Type: "ordinary", Size: 16, AuthRead: true},
	}}}

	result, err := newMCPProviderWithTPM(tpm).TPMNVList(context.Background())

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"indexes": []map[string]interface{}{{
		"handle": uint32(testNVIndex), "type": "ordinary", "size": uint32(16), "auth_read": true, "auth_write": false,
	}}}, result)
}

func TestMCPServiceProvider_TPMNVList_PropagatesError(t *testing.T) {
	_, err := newMCPProviderWithTPM(&nvPCRTPM{propsErr: errPropertiesFailed}).TPMNVList(context.Background())

	assert.ErrorIs(t, err, errPropertiesFailed)
}

func TestMCPServiceProvider_TPMNV_WriteReadDelete(t *testing.T) {
	ctx := context.Background()
	tpm := newNVTPM()
	p := newMCPProviderWithTPM(tpm)

	_, err := p.TPMNVWrite(ctx, testNVIndex, []byte("abcd"), 2, "pw")
	require.NoError(t, err)

	data, err := p.TPMNVRead(ctx, testNVIndex, 4, 2, "pw")
	require.NoError(t, err)
	assert.Equal(t, []byte("abcd"), data)

	_, err = p.TPMNVDelete(ctx, testNVIndex, "owner")
	require.NoError(t, err)
	_, defined := tpm.nv.Data(testNVIndex)
	assert.False(t, defined)
}

func TestMCPServiceProvider_TPMNV_Errors(t *testing.T) {
	ctx := context.Background()
	p := newMCPProviderWithTPM(newNVTPM())
	noTransport := newMCPProviderWithTPM(&nvPCRTPM{})

	tests := []struct {
		name string
		call func() error
		want error
		code codes.Code
	}{
		{"read index 0", func() error { _, err := p.TPMNVRead(ctx, 0, 0, 0, ""); return err }, tpmnv.ErrIndexRequired{}, codes.InvalidArgument},
		{"write no data", func() error { _, err := p.TPMNVWrite(ctx, testNVIndex, nil, 0, "pw"); return err }, tpmnv.ErrDataRequired{}, codes.InvalidArgument},
		{"delete index 0", func() error { _, err := p.TPMNVDelete(ctx, 0, "owner"); return err }, tpmnv.ErrIndexRequired{}, codes.InvalidArgument},
		{"read no transport", func() error { _, err := noTransport.TPMNVRead(ctx, testNVIndex, 0, 0, ""); return err }, tpmnv.ErrTransportUnavailable{}, codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			assert.ErrorIs(t, err, tt.want)
			assert.Equal(t, tt.code, status.Code(err))
		})
	}

	_, err := p.TPMNVWrite(ctx, testNVIndex, []byte("x"), 0, "wrong")
	assert.Error(t, err, "a wrong index password is refused by the TPM")
	_, err = p.TPMNVDelete(ctx, testNVIndex, "wrong")
	assert.Error(t, err, "a wrong owner password is refused by the TPM")
}

func newTPMGRPCServiceWith(tpm xkmssdk.TrustedPlatformModule) *TPMGRPCService {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(tpm)
	return svc
}

func TestTPMGRPCService_NVRAM_WriteReadUndefine(t *testing.T) {
	ctx := context.Background()
	tpm := newNVTPM()
	svc := newTPMGRPCServiceWith(tpm)

	_, err := svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{Index: testNVIndex, Data: []byte("abcd"), Offset: 2, Password: "pw"})
	require.NoError(t, err)

	rsp, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: testNVIndex, Size: 4, Offset: 2, Password: "pw"})
	require.NoError(t, err)
	assert.Equal(t, []byte("abcd"), rsp.GetData())

	whole, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: testNVIndex, Size: math.MaxUint32, Password: "pw"})
	require.NoError(t, err)
	assert.Len(t, whole.GetData(), 16, "a size past 65535 reads the whole index")

	_, err = svc.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{Index: testNVIndex, ParentPassword: "owner"})
	require.NoError(t, err)
	_, defined := tpm.nv.Data(testNVIndex)
	assert.False(t, defined)
}

func TestTPMGRPCService_NVRAM_ErrorCodes(t *testing.T) {
	ctx := context.Background()
	svc := newTPMGRPCServiceWith(newNVTPM())
	noTransport := newTPMGRPCServiceWith(&nvPCRTPM{})
	unwired := NewTPMGRPCService(logging.NewLogger(0, nil))

	tests := []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"read index 0", func() error {
			_, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{})
			return err
		}, codes.InvalidArgument},
		{"write no data", func() error {
			_, err := svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{Index: testNVIndex})
			return err
		}, codes.InvalidArgument},
		{"write offset past 16 bits", func() error {
			_, err := svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{Index: testNVIndex, Data: []byte("x"), Offset: math.MaxUint16 + 1})
			return err
		}, codes.InvalidArgument},
		{"read offset past 16 bits", func() error {
			_, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: testNVIndex, Offset: math.MaxUint16 + 1})
			return err
		}, codes.InvalidArgument},
		{"undefine index 0", func() error {
			_, err := svc.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{})
			return err
		}, codes.InvalidArgument},
		{"no transport", func() error {
			_, err := noTransport.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: testNVIndex})
			return err
		}, codes.Unavailable},
		{"no TPM", func() error {
			_, err := unwired.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{Index: testNVIndex})
			return err
		}, codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, status.Code(tt.call()))
		})
	}
}

func TestNVOffset(t *testing.T) {
	offset, err := nvOffset(math.MaxUint16)
	require.NoError(t, err)
	assert.Equal(t, uint16(math.MaxUint16), offset)

	_, err = nvOffset(math.MaxUint16 + 1)
	assert.ErrorIs(t, err, ErrNVOffsetOutOfRange{Offset: math.MaxUint16 + 1})
	assert.EqualError(t, err, "NV offset 65536 exceeds maximum 65535")
}

func TestMapError_KeepsTypedStatus(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))

	err := svc.mapError(tpmnv.ErrTransportUnavailable{})

	assert.Equal(t, codes.Unavailable, status.Code(err), "a typed status survives the TPM-substring fallback")
}
