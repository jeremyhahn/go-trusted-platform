package webservice

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type Signer struct {
	logger   *logging.Logger
	ca       ca.CertificateAuthority
	cert     *x509.Certificate
	cn       string
	password []byte
	crypto.Signer
}

func NewSigner(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	cert *x509.Certificate,
	cn string,
	password []byte) *Signer {

	return &Signer{
		logger:   logger,
		ca:       ca,
		cert:     cert,
		cn:       cn,
		password: password}
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.cert.PublicKey
}

func (signer *Signer) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) ([]byte, error) {

	signer.logger.Info("webserivce: signing digest: %s", digest)

	attrs := &keystore.KeyAttributes{
		CN:       signer.cert.Subject.CommonName,
		Password: keystore.NewClearPassword(signer.password),
	}

	s, err := signer.ca.Signer(attrs)
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}

	return s.Sign(rand, digest, opts)
}
