package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/op/go-logging"
)

type SigningKey struct {
	logger   *logging.Logger
	ca       CertificateAuthority
	pub      crypto.PublicKey
	password []byte
	crypto.Signer
}

// Signs the requested data using the Certificate Authority Private Key, or the
// specified key provided by SigningOpts. An optional hash function can also be
// configured. RSA keys use Probablistic Signature Scheme (PSS) padding, which
// is more secure, however, incompatible with some use cases, such as TLS. Use
// the PKCS1v15 signer for those specific cases.
// https://github.com/golang/go/blob/819e3394c90e27483f1f6eabfb02d22c927a139d/src/crypto/tls/handshake_client_test.go#L2385
// https://github.com/golang/go/issues/30416#issuecomment-468527899
func NewSigningKey(
	logger *logging.Logger,
	ca CertificateAuthority,
	password []byte,
	publicKey crypto.PublicKey) SigningKey {

	return SigningKey{
		logger:   logger,
		ca:       ca,
		password: password,
		pub:      publicKey,
	}
}

// Returns the public key used to sign
func (signer SigningKey) Public() crypto.PublicKey {
	return signer.pub
}

// Signs the requested digest
func (signer SigningKey) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	signingOpts, ok := opts.(SigningOpts)
	if !ok {
		return nil, fmt.Errorf("signer: invalid signing opts: %T. ca.SigningOpts required", opts)
	}

	var privateKey crypto.PrivateKey
	// Set options and load private key per specified options
	pssOpts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	if opts != nil {
		// Set PSS salt length if provided
		if signingOpts.PSSSaltLength != 0 {
			pssOpts.SaltLength = signingOpts.PSSSaltLength
		}
		// Get a signing key if provided
		if signingOpts.KeyCN != nil && signingOpts.KeyName != nil {
			privateKey, err = signer.ca.PrivKey(
				*signingOpts.KeyCN,
				*signingOpts.KeyName,
				signer.password,
				PARTITION_SIGNING_KEYS)
		}
	}
	if privateKey == nil && err == nil {
		// No signing key, use CA private key to sign
		privateKey, err = signer.ca.CAPrivKey(signer.password)
	}
	// Handle errors from private key lookup
	if err != nil {
		return nil, err
	}
	rsaPriv, isRSA := privateKey.(*rsa.PrivateKey)
	eccPriv, isECDSA := privateKey.(*ecdsa.PrivateKey)
	if isRSA {
		signature, err = rsa.SignPSS(
			rand, rsaPriv, opts.HashFunc(), signingOpts.Digest(), &pssOpts)
	} else if isECDSA {
		signature, err = ecdsa.SignASN1(rand, eccPriv, signingOpts.Digest())
	}
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}
	// Save the signature to the blob store if enabled
	if opts != nil {
		if signingOpts.StoreSignature && signingOpts.BlobKey != nil {
			sigKey := fmt.Sprintf("%s%s", *signingOpts.BlobKey, FSEXT_SIG)
			if err := signer.ca.ImportBlob(sigKey, signature); err != nil {
				return nil, err
			}
		}
		if signingOpts.BlobKey != nil && signingOpts.BlobData != nil {
			// Save the digest
			digestFile := fmt.Sprintf("%s%s",
				*signingOpts.BlobKey,
				FSEXT_DIGEST)
			if err := signer.ca.ImportBlob(digestFile, digest); err != nil {
				return nil, err
			}
			// Save a checksum
			checksumFile := fmt.Sprintf("%s.%s",
				*signingOpts.BlobKey,
				signer.ca.HashFileExtension(signer.ca.Hash()))
			checksum := hex.EncodeToString(digest)
			if err := signer.ca.ImportBlob(checksumFile, []byte(checksum)); err != nil {
				return nil, err
			}
			// Save the data
			if err := signer.ca.ImportBlob(*signingOpts.BlobKey, signingOpts.BlobData); err != nil {
				return nil, err
			}
		}
	}
	return signature, nil
}
