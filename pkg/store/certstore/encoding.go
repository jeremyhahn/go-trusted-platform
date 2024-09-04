package certstore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Encodes a raw DER byte array as a PEM byte array
func EncodePEM(derCert []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if err != nil {
		return nil, err
	}
	return caPEM.Bytes(), nil
}

// Decodes PEM bytes to *x509.Certificate
func DecodePEM(bytes []byte) (*x509.Certificate, error) {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, keystore.ErrInvalidEncodingPEM
	}
	return x509.ParseCertificate(block.Bytes)
}

// Encodes a Certificate Signing Request to PEM form
func EncodeCSR(csr []byte) ([]byte, error) {
	csrPEM := new(bytes.Buffer)
	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}
	if err := pem.Encode(csrPEM, csrBlock); err != nil {
		return nil, err
	}
	return csrPEM.Bytes(), nil
}

// Decodes CSR bytes to x509.CertificateRequest
func DecodeCSR(bytes []byte) (*x509.CertificateRequest, error) {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, keystore.ErrInvalidEncodingPEM
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// Decodes a PEM certificate chain
func DecodePEMChain(bytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for block, rest := pem.Decode(bytes); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(err)
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}
