package daemon

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// akCreatingTPM is a TPM fake whose CreateIAK returns a key with a public
// key, so CreateAK can be checked for carrying it in its answer.
type akCreatingTPM struct {
	xkmssdk.TrustedPlatformModule
}

func (t *akCreatingTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return attrsKey(0x81010001, x509.RSA), nil
}

func (t *akCreatingTPM) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle:         xkmssdk.TPMHandle(0x81010002),
			PublicKeyBytes: []byte("ak-pub"),
		},
	}, nil
}

// TestTPMGRPCService_CreateAKReturnsPublicKey checks that the CreateAK answer
// carries the created AK's public key, as GetAK does (#2068).
func TestTPMGRPCService_CreateAKReturnsPublicKey(t *testing.T) {
	svc := NewTPMGRPCService(logging.DefaultLogger())
	svc.SetTPM2Service(&akCreatingTPM{})

	resp, err := svc.CreateAK(context.Background(), &platformv1.CreateAKRequest{})
	require.NoError(t, err)
	assert.Equal(t, []byte("ak-pub"), resp.GetPublicKey())
	assert.Equal(t, uint32(0x81010002), resp.GetHandle())
}
