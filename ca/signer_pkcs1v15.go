package ca

import (
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/op/go-logging"
)

type PKCS1v15SigningKey struct {
	logger   *logging.Logger
	ca       CertificateAuthority
	pub      crypto.PublicKey
	password []byte
	crypto.Signer
}

// Signs the requested data using the specified public key and hash function.
// This padding scheme is insecure and not recommended for modern implementations,
// and only provided for backward compatibility, such as TLS.
// https://github.com/golang/go/blob/819e3394c90e27483f1f6eabfb02d22c927a139d/src/crypto/tls/handshake_client_test.go#L2385
// https://github.com/golang/go/issues/30416#issuecomment-468527899
func NewPKCS1v15SigningKey(
	logger *logging.Logger,
	ca CertificateAuthority,
	password []byte,
	publicKey crypto.PublicKey) PKCS1v15SigningKey {

	return PKCS1v15SigningKey{
		logger:   logger,
		ca:       ca,
		password: password,
		pub:      publicKey,
	}
}

// Returns the signing public key
func (signer PKCS1v15SigningKey) Public() crypto.PublicKey {
	return signer.pub
}

// Signs the requested digest using PKCS1 v1.5 padding
func (signer PKCS1v15SigningKey) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	signingOpts, ok := opts.(SignerOpts)
	if !ok {
		return nil, ErrInvalidSignerOpts
	}
	var privateKey crypto.PrivateKey
	if opts != nil {
		// Load the key provided by signing opts
		if signingOpts.KeyCN != nil && signingOpts.KeyName != nil {
			privateKey, err = signer.ca.PrivKey(
				*signingOpts.KeyCN,
				*signingOpts.KeyName,
				signer.password,
				PARTITION_SIGNING_KEYS)
		}
	}
	// Use the CA key if a key wasn't provided
	if privateKey == nil {
		privateKey, err = signer.ca.CAPrivKey(signer.password)
	}
	if err != nil {
		return nil, err
	}
	privKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKeyRSA
	}

	// Sign
	signature, err = rsa.SignPKCS1v15(rand, privKey, signingOpts.HashFunc(), digest)
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}
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
