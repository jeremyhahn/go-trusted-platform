package tpmowner

import (
	"errors"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"
)

func TestParseSOPINRef_Valid(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want SOPINRef
	}{
		{name: "literal", ref: "123456", want: SOPINRef{Literal: []byte("123456")}},
		{
			name: "kms ensure",
			ref:  "kms://platform/so-pin?ensure=true&len=8&enc=numeric",
			want: SOPINRef{KMSPath: "platform/so-pin", Length: 8},
		},
		{
			name: "kms query order",
			ref:  "kms://so-pin?enc=numeric&len=12&ensure=1",
			want: SOPINRef{KMSPath: "so-pin", Length: 12},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseSOPINRef(tt.ref)
			require.NoError(t, err)
			require.Equal(t, tt.want, *ref)
			require.Equal(t, tt.want.KMSPath != "", ref.IsKMS())
		})
	}
}

func TestParseSOPINRef_Refused(t *testing.T) {
	tests := []struct {
		name string
		ref  string
	}{
		{name: "default password", ref: xkmssdk.DEFAULT_PASSWORD},
		{name: "other scheme", ref: "file:///etc/so-pin"},
		{name: "kms without ensure", ref: "kms://so-pin?len=8&enc=numeric"},
		{name: "kms ensure false", ref: "kms://so-pin?ensure=false&len=8&enc=numeric"},
		{name: "kms not numeric", ref: "kms://so-pin?ensure=true&len=8&enc=base64"},
		{name: "kms no length", ref: "kms://so-pin?ensure=true&enc=numeric"},
		{name: "kms zero length", ref: "kms://so-pin?ensure=true&len=0&enc=numeric"},
		{name: "kms no path", ref: "kms://?ensure=true&len=8&enc=numeric"},
		{name: "kms bad query", ref: "kms://so-pin?ensure=true&len=8&enc=numeric&%zz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseSOPINRef(tt.ref)
			require.Nil(t, ref)
			var refErr *SOPINRefError
			require.ErrorAs(t, err, &refErr)
		})
	}
}

func TestParseSOPINRef_Empty(t *testing.T) {
	ref, err := ParseSOPINRef("")
	require.Nil(t, ref)
	require.ErrorIs(t, err, ErrSOPINNotConfigured)
}

// The refusal names the URI's shape, never a literal PIN.
func TestParseSOPINRef_ErrorOmitsLiteral(t *testing.T) {
	_, err := ParseSOPINRef("secret://hunter2")
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "hunter2"))
}

func TestGenerateNumericSOPIN(t *testing.T) {
	pin, err := GenerateNumericSOPIN(12)
	require.NoError(t, err)
	require.Len(t, pin, 12)
	for _, c := range pin {
		require.True(t, c >= '0' && c <= '9', "every byte is an ASCII digit")
	}
}

func TestGenerateNumericSOPIN_InvalidLength(t *testing.T) {
	pin, err := GenerateNumericSOPIN(0)
	require.Nil(t, pin)
	require.ErrorIs(t, err, ErrSOPINLengthInvalid)
}

type failingReader struct{}

var errInjectedEntropy = errors.New("injected entropy failure")

func (failingReader) Read([]byte) (int, error) { return 0, errInjectedEntropy }

func TestGenerateNumericSOPIN_EntropyFault(t *testing.T) {
	restore := entropy
	t.Cleanup(func() { entropy = restore })
	entropy = failingReader{}

	pin, err := GenerateNumericSOPIN(8)
	require.Nil(t, pin)
	var genErr *SOPINGenerateError
	require.ErrorAs(t, err, &genErr)
	require.ErrorIs(t, err, errInjectedEntropy)
}
