package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Creates a new signing key that matches the same algorithm configuration
// of the Certificate Authority (RSA / ECC).
func (ca *CA) NewSigningKey(cn, keyName string, password []byte) (crypto.Signer, error) {
	if ca.params.Config.KeyAlgorithm == KEY_ALGO_RSA {
		return ca.NewRSASigningKey(cn, keyName, password)
	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		return ca.NewECDSASigningKey(cn, keyName, password)
	}
	return nil, ErrInvalidAlgorithm
}

// Returns a signing key from the key store or ErrKeyDoesntExist if the
// key does not exist
func (ca *CA) SigningKey(cn, keyName string, password []byte) (SigningKey, error) {
	keyDER, err := ca.certStore.Get(cn, keyName, PARTITION_SIGNING_KEYS, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return SigningKey{}, err
	}
	pub, err := x509.ParsePKIXPublicKey(keyDER)
	if err != nil {
		ca.params.Logger.Error(err)
		return SigningKey{}, err
	}
	return NewSigningKey(ca.params.Logger, ca, password, pub), nil
}

// Creates a new RSA signing key for the requested common name and
// returns a crypto.Signer implementation that supports RSA-PSS padding
// scheme. Private signing keys are never returned from from the
// Certificate Authority, and are stored in a separate partition /
// hierarchy for security and longevity.
func (ca *CA) NewRSASigningKey(cn, keyName string, password []byte) (crypto.Signer, error) {
	// Ensure password confirms to requirements and
	// retrieve encryption flag
	isEncrypted, err := ca.checkPassword(password)
	if err != nil {
		return nil, err
	}
	// Private Key: Create
	privateKey, err := rsa.GenerateKey(ca.params.Random, ca.identity.KeySize)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	publicKey := &privateKey.PublicKey
	// Create the signing key and return a the default
	// crypto.Signer for RSS-PSA and ECC keys
	err = ca.createSigningKey(
		cn,
		keyName,
		password,
		privateKey,
		&privateKey.PublicKey,
		isEncrypted)
	return NewSigningKey(ca.params.Logger, ca, password, publicKey), nil
}

// Creates a new ECDSA signing key for the requested common name and
// returns a crypto.Signer implementation that uses the new public key.
func (ca *CA) NewECDSASigningKey(cn, keyName string, password []byte) (crypto.Signer, error) {
	// Ensure password confirms to requirements and
	// retrieve encryption flag
	isEncrypted, err := ca.checkPassword(password)
	if err != nil {
		return nil, err
	}
	// Private Key: Create
	privateKey, err := ecdsa.GenerateKey(ca.curve, ca.params.Random)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	publicKey := &privateKey.PublicKey
	// Create the signing key and return a the default
	// crypto.Signer for RSS-PSA and ECC keys
	err = ca.createSigningKey(
		cn,
		keyName,
		password,
		privateKey,
		publicKey,
		isEncrypted)
	if err != nil {
		return nil, err
	}
	// Return the crypto.Signer signing key
	return NewSigningKey(ca.params.Logger, ca, password, publicKey), nil
}

// Creates a new RSA signing key for the requested common name and
// returns the PKCS1v15 crypto.Signer implementation that uses the new public
// key.
func (ca *CA) NewPKCS1v15SigningKey(cn, keyName string, password []byte) (crypto.Signer, error) {
	// Ensure password confirms to requirements and
	// retrieve encryption flag
	isEncrypted, err := ca.checkPassword(password)
	if err != nil {
		return nil, err
	}
	// Private Key: Create
	privateKey, err := rsa.GenerateKey(ca.params.Random, ca.identity.KeySize)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	publicKey := &privateKey.PublicKey
	// Create the signing key and return a the default
	// crypto.Signer for RSS-PSA and ECC keys
	err = ca.createSigningKey(
		cn,
		keyName,
		password,
		privateKey,
		&privateKey.PublicKey,
		isEncrypted)
	return NewPKCS1v15SigningKey(ca.params.Logger, ca, password, publicKey), nil
}

// Creates a new signing key and returns the RSA-PSS / ECDSA crypto.Signer
func (ca *CA) createSigningKey(
	cn, keyName string,
	password []byte,
	privateKey crypto.PrivateKey,
	publicKey crypto.PublicKey,
	isEncrypted bool) error {

	// Private Key: Marshal to PKCS8 (w/ optional password)
	pkcs8, err := ca.EncodePrivKey(privateKey, password)
	err = ca.certStore.SaveKeyed(
		cn, keyName, pkcs8, PARTITION_SIGNING_KEYS, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Private Key: Encode to PEM
	pkcs8PEM, err := ca.EncodePrivKeyPEM(pkcs8, isEncrypted)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Private Key: Save PKCS8 PEM encoded key
	err = ca.certStore.SaveKeyed(
		cn, keyName, pkcs8PEM, PARTITION_SIGNING_KEYS, FSEXT_PRIVATE_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Public Key: Encode to PKIX, ASN.1 DER form
	pubKeyDER, err := ca.EncodePubKey(publicKey)
	if err != nil {
		return err
	}
	// Public Key: Save the ASN.1 DER PKCS1 form
	err = ca.certStore.SaveKeyed(
		cn, keyName, pubKeyDER, PARTITION_SIGNING_KEYS, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return err
	}
	// Public Key: Encdode to PEM form
	pubPEM, err := ca.EncodePubKeyPEM(cn, pubKeyDER)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	// Public Key: Save PEM form
	err = ca.certStore.SaveKeyed(cn, keyName, pubPEM, PARTITION_SIGNING_KEYS, FSEXT_PUBLIC_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return err
	}
	return nil
}

// Verifies a RSA-PSS or ECDSA digest
// Options:
// 1. KeyCN: An optional signing key. Default is CA public key.
// 2. Hash:  An optional cypto.Hash signing algorithm. Default is SHA256.
// 3. UseStoredSignature: Uses opts.KeyCN public key for verification
func (ca *CA) VerifySignature(digest, signature []byte, opts *VerifyOpts) error {
	var err error
	publicKey := ca.Public()
	hashAlgo := ca.Hash()
	pssOpts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	if opts != nil {
		if opts.PSSSaltLength != 0 {
			pssOpts.SaltLength = *&opts.PSSSaltLength
		}
		if opts.Hash != nil {
			hashAlgo = *opts.Hash
		}
		if opts.KeyCN != nil && opts.KeyName != nil {
			publicKey, err = ca.certStore.PubKey(
				*opts.KeyCN, *opts.KeyName, PARTITION_SIGNING_KEYS)
		}
		if opts.UseStoredSignature && opts.BlobKey != nil {
			sig, err := ca.Signature(*opts.BlobKey)
			if err != nil {
				ca.params.Logger.Error(err)
				return err
			}
			signature = sig
		}
	}
	if ca.params.Config.KeyAlgorithm == KEY_ALGO_RSA {
		if publicKey == nil && err == nil {
			publicKey, err = ca.certStore.CAPubKey()
		}
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		rsaPub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyRSA
		}
		err := rsa.VerifyPSS(rsaPub, hashAlgo, digest, signature, &pssOpts)
		if err != nil {
			ca.params.Logger.Error(err)
			return err
		}
	} else if ca.params.Config.KeyAlgorithm == KEY_ALGO_ECC {
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		eccPub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyRSA
		}
		if ok := ecdsa.VerifyASN1(eccPub, digest, signature); !ok {
			return ErrInvalidSignature
		}
	} else {
		return ErrInvalidAlgorithm
	}
	return nil
}

// Verifies the requested RSA PKCS1v15 digest.
// Options:
// 1. KeyCN: An optional signing key. Default is CA public key.
// 2. Hash:  An optional cypto.Hash signing algorithm. Default is SHA256.
// 3. UseStoredSignature: Uses opts.KeyCN public key for verification
func (ca *CA) VerifyPKCS1v15(digest, signature []byte, opts *VerifyOpts) error {
	var publicKey crypto.PublicKey
	var err error
	hashAlgo := ca.Hash()
	if opts != nil {
		// Set optional hash
		if opts.Hash != nil {
			hashAlgo = *opts.Hash
		}
		// Use signing key instad of CA
		if opts.KeyCN != nil {
			publicKey, err = ca.certStore.PubKey(
				*opts.KeyCN, *opts.KeyName, PARTITION_SIGNING_KEYS)
		}
		if opts.UseStoredSignature {
			sig, err := ca.Signature(*opts.BlobKey)
			if err != nil {
				return err
			}
			signature = sig
		}
	} else {
		publicKey, err = ca.certStore.CAPubKey()
	}
	if err != nil {
		return err
	}
	rsaPub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidPublicKeyRSA
	}
	// Use the signature to verify the digest
	if err := rsa.VerifyPKCS1v15(rsaPub, hashAlgo, digest, signature); err != nil {
		ca.params.Logger.Error(err)
		return ErrInvalidSignature
	}
	return nil
}

// Signs a digest using the Certificate Authority public key
// Implements crypto.Signer
func (ca *CA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	pub, err := ca.CAPubKey()
	if err != nil {
		return nil, err
	}
	if ca.params.Config.RSAScheme == RSA_SCHEME_RSAPSS {
		signer := NewSigningKey(ca.params.Logger, ca, ca.params.Password, pub)
		return signer.Sign(ca.params.Random, digest, opts)
	} else if ca.params.Config.RSAScheme == RSA_SCHEME_PKCS1v15 {
		signer := NewPKCS1v15SigningKey(
			ca.params.Logger, ca, ca.params.Password, pub)
		return signer.Sign(ca.params.Random, digest, opts)
	} else {
		return nil, fmt.Errorf("%s: %s",
			ErrUnsupportedSigningAlgorithm, ca.params.Config.RSAScheme)
	}
}

// Returns a stored signature from the signed blob store
func (ca *CA) Signature(key string) ([]byte, error) {
	sigKey := fmt.Sprintf("%s%s", key, FSEXT_SIG)
	return ca.certStore.Blob(sigKey)
}

// Returns true if the specified common name has a stored signature
func (ca *CA) Signed(key string) (bool, error) {
	sigKey := fmt.Sprintf("%s%s", key, FSEXT_SIG)
	if _, err := ca.certStore.Blob(sigKey); err != nil {
		return false, err
	}
	return true, nil
}

// Returns signed data from the signed blob store
func (ca *CA) SignedData(key string) ([]byte, error) {
	return ca.certStore.Blob(key)
}

// Returns a blob signed digest from blob storage
func (ca *CA) Digest(key string, hash crypto.Hash) (bool, error) {
	digestKey := fmt.Sprintf("%s%s", key, FSEXT_DIGEST)
	if _, err := ca.certStore.Blob(digestKey); err != nil {
		return false, err
	}
	return true, nil
}

// Returns a blob checksum (hex)
func (ca *CA) Checksum(key string) (bool, error) {
	checksumKey := fmt.Sprintf("%s.%s", key, ca.HashFileExtension(ca.Hash()))
	if _, err := ca.certStore.Blob(checksumKey); err != nil {
		return false, err
	}
	return true, nil
}

// Converts a hash function name to a file extension. Used to
// save a signed digest file with an appropriate file extension
// to the blob store.
func (ca *CA) HashFileExtension(hash crypto.Hash) string {
	name := strings.ToLower(hash.String())
	name = strings.ReplaceAll(name, "-", "")
	return name
}
