package endorse01

import (
	"net"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

// Implements acme.ChallengeVerifierFunc
func Verify(
	resolver *net.Resolver,
	ca ca.CertificateAuthority,
	domain, port, challengeToken, expectedKeyAuth string) error {

	// TODO: Add support for ACME EAB to authenticate endorse-01 requests.
	return nil
}

func Setup(
	challengeToken string,
	certAuthority ca.CertificateAuthority,
	tpm tpm2.TrustedPlatformModule) ([]byte, error) {

	ekPubKey := tpm.EK()
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, err
	}

	serializer, err := keystore.NewSerializer(serializer.SERIALIZER_JSON)
	if err != nil {
		return nil, err
	}

	ekPubKeyBytes, err := serializer.Serialize(ekPubKey)
	if err != nil {
		return nil, err
	}

	csr, err := certAuthority.CreateCSR(ca.CertificateRequest{
		PermanentID:   string(ekPubKeyBytes),
		KeyAttributes: ekAttrs,
		Subject: ca.Subject{
			CommonName: ekAttrs.CN,
		},
	})
	if err != nil {
		return nil, err
	}

	return csr, nil
}
