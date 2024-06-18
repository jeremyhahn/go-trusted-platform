package webservice

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/op/go-logging"
)

type Signer struct {
	logger *logging.Logger
	ca     ca.CertificateAuthority
	cert   *x509.Certificate
	cn     string
	crypto.Signer
}

func NewSigner(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	cert *x509.Certificate,
	cn string) *Signer {

	return &Signer{
		logger: logger,
		ca:     ca,
		cert:   cert,
		cn:     cn}
}

func (signer *Signer) Public() crypto.PublicKey {
	signer.logger.Info("signer.Public")
	return signer.cert.PublicKey
}

func (signer *Signer) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) ([]byte, error) {

	signer.logger.Info("signer.Sign")

	signer.logger.Info("retrieving private PEM key from cert store")
	privPEM, err := signer.ca.CertStore().PrivKeyPEM(signer.cn)
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}

	signer.logger.Info("retrieving public PEM key from cert store")
	pubPEM, err := signer.ca.CertStore().PubKeyPEM(signer.cn)
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}

	signer.logger.Info("creating x509 key pair")
	tlsCert, err := tls.X509KeyPair(pubPEM, privPEM)
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}

	signer.logger.Info("sign using %T\n", tlsCert.PrivateKey)

	return tlsCert.PrivateKey.(crypto.Signer).Sign(rand, digest, opts)
}
