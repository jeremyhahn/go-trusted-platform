package deviceattest01

import (
	"crypto/x509"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

type AttestationFormat string

const (
	ATTESTATION_FORMAT_TPM = "tpm"
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

func Verify(domain, token, keyAuth string) error {
	return nil
}

func GenerateStatement(
	challengeToken string,
	keyAttrs *keystore.KeyAttributes,
	format AttestationFormat,
	tpm tpm2.TrustedPlatformModule) ([]byte, error) {

	var alg int64
	switch keyAttrs.KeyAlgorithm {
	case x509.RSA:
		alg = int64(-257) // AlgRS256
	case x509.ECDSA:
		alg = int64(-7) // AlgES256
	case x509.Ed25519:
		alg = int64(-8) // AlgEdDSA
	default:
		return nil, keystore.ErrInvalidKeyAlgorithm
	}

	// var certBytes, sig, certifyInfo, pubArea []byte
	// var err error

	// switch format {
	// case ATTESTATION_FORMAT_TPM:
	// 	ekCert, err := tpm.EKCertificate()
	// 	certBytes = ekCert.Raw

	// 	quote, err := tpm.Quote([]uint{14}, []byte(challengeToken))
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	sig = quote.Signature
	// 	// certifyInfo = quote.Quoted.CertifyInfo
	// 	// pubArea = quote.Quoted.PubArea
	// }

	if keyAttrs.TPMAttributes == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	certBytes := keyAttrs.TPMAttributes.PublicKeyBytes
	certifyInfo := keyAttrs.TPMAttributes.CertifyInfo
	pubArea := keyAttrs.TPMAttributes.BPublic.Bytes()
	sig := keyAttrs.TPMAttributes.Signature

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
	return b, nil
}
