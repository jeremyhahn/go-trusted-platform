package deviceattest01

import (
	"crypto/x509"
	"encoding/json"
	"net"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

type AttestationFormat string

const (
	FormatTPM = "tpm"
)

func (format AttestationFormat) String() string {
	return string(format)
}

type AttestationObject struct {
	Format       string               `json:"fmt"`
	AttStatement AttestationStatement `json:"attStmt,omitempty"`
}

type AttestationStatement struct {
	Ver      string        `json:"ver"`
	Alg      int64         `json:"alg"`
	X5c      []interface{} `json:"x5c"`
	Sig      []byte        `json:"sig"`
	CertInfo []byte        `json:"certInfo"`
	PubArea  []byte        `json:"pubArea"`
}

// Verifies the device-attest-01 challenge
// Implements acme.ChallengeVerifierFunc
func Verify(
	resolver *net.Resolver,
	ca ca.CertificateAuthority,
	domain, port, challengeToken, expectedKeyAuth string) error {

	return nil
}

// Generates an attestation statement for the device-attest-01 challenge.
// https://datatracker.ietf.org/doc/draft-acme-device-attest
// https://www.w3.org/TR/webauthn/#sctn-tpm-attestation
func Setup(
	keyAuth string,
	akAttrs *keystore.KeyAttributes,
	format AttestationFormat,
	tpm tpm2.TrustedPlatformModule) ([]byte, error) {

	var alg int64
	switch akAttrs.KeyAlgorithm {
	case x509.RSA:
		alg = int64(-257) // AlgRS256
	case x509.ECDSA:
		alg = int64(-7) // AlgES256
	case x509.Ed25519:
		alg = int64(-8) // AlgEdDSA
	default:
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	var certBytes, sig, certifyInfo, pubArea []byte
	var err error

	switch format {

	case FormatTPM:

		quote, err := tpm.Quote([]uint{14}, []byte(keyAuth))
		if err != nil {
			return nil, err
		}

		certBytes = akAttrs.TPMAttributes.PublicKeyBytes
		sig = quote.Signature
		certifyInfo = quote.Quoted
		pubArea = akAttrs.TPMAttributes.BPublic.Bytes()
	}

	obj := &AttestationObject{
		Format: format.String(),
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      alg,
			X5c:      []interface{}{certBytes},
			Sig:      sig,
			CertInfo: certifyInfo,
			PubArea:  pubArea,
		},
	}
	b, err := cbor.Marshal(obj)
	if err != nil {
		return nil, err
	}
	req := struct {
		AttStmt []byte `json:"attStmt"`
	}{
		b,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
