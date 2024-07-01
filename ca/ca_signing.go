package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// Creates a new RSA signing key for the requested common name and
// returns the public half of the key. Private signing keys are
// never returned from from the Certificate Authority, and are stored
// in a separate partition / hierarchy for security and longevity.
func (ca *CA) NewSigningKey(cn, keyName string, password, caPassword []byte) (crypto.PublicKey, error) {
	// Check private key password and complexity requirements
	encrypted := false
	if ca.params.Config.RequirePrivateKeyPassword {
		if password == nil {
			return nil, ErrPrivateKeyPasswordRequired
		}
		if !ca.passwordPolicy.MatchString(string(password)) {
			return nil, ErrPasswordComplexity
		}
		encrypted = true
	}
	// Private Key: Create
	privateKey, err := rsa.GenerateKey(ca.params.Random, ca.identity.KeySize)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Private Key: Marshal to PKCS8 (w/ optional password)
	pkcs8, err := ca.EncodePrivKey(privateKey, password)
	err = ca.certStore.SaveKeyed(
		cn, keyName, pkcs8, PARTITION_SIGNING_KEYS, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Private Key: Encode to PEM
	pkcs8PEM, err := ca.EncodePrivKeyPEM(pkcs8, encrypted)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Private Key: Save PKCS8 PEM encoded key
	err = ca.certStore.SaveKeyed(
		cn, keyName, pkcs8PEM, PARTITION_SIGNING_KEYS, FSEXT_PRIVATE_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Public Key: Encode to PKIX, ASN.1 DER form
	pubKeyDER, err := ca.EncodePubKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	// Public Key: Save the ASN.1 DER PKCS1 form
	err = ca.certStore.SaveKeyed(
		cn, keyName, pubKeyDER, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}
	// Public Key: Encdode to PEM form
	pubPEM, err := ca.EncodePubKeyPEM(cn, pubKeyDER)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Public Key: Save DER form
	err = ca.certStore.SaveKeyed(cn, keyName, pubKeyDER, PARTITION_SIGNING_KEYS, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Public Key: Save PEM form
	err = ca.certStore.SaveKeyed(cn, keyName, pubPEM, PARTITION_SIGNING_KEYS, FSEXT_PUBLIC_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

// Signs the requested data using the Certificate Authority Private Key and
// optional hash function. SHA256 is used as the default hash function if not provided.
// RSA keys use Probablistic Signature Scheme (PSS) padding, which is more secure,
// however, incompatible with some use cases, such as TLS. Use the Sign/Verify PKCS1v15
// padding for those specific cases.
// https://github.com/golang/go/blob/819e3394c90e27483f1f6eabfb02d22c927a139d/src/crypto/tls/handshake_client_test.go#L2385
// https://github.com/golang/go/issues/30416#issuecomment-468527899
func (ca *CA) Sign(data []byte, password []byte, opts *SigningOpts) ([]byte, []byte, error) {
	var signature, digest []byte
	var privateKey crypto.PrivateKey
	var err error
	// Set options and load private key per specified options
	pssOpts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	hashAlgo := crypto.SHA256
	if opts != nil {
		// Set PSS salt length if provided
		if opts.PSSSaltLength != 0 {
			pssOpts.SaltLength = *&opts.PSSSaltLength
		}
		// Set hash algorithm if provided
		if opts.Hash != nil {
			hashAlgo = *opts.Hash
		}
		// Get a signing key if provided
		if opts.KeyCN != nil && opts.KeyName != nil {
			privateKey, err = ca.certStore.PrivKey(
				*opts.KeyCN, *opts.KeyName, password, PARTITION_SIGNING_KEYS)
		}
	}
	if privateKey == nil && err == nil {
		// No signing key, use CA private key to sign
		privateKey, err = ca.certStore.CAPrivKey(password)
	}
	// Handle errors from private key lookup
	if err != nil {
		return nil, nil, err
	}
	// Try to parse the key as RSA
	rsaPriv, isRSA := privateKey.(*rsa.PrivateKey)
	eccPriv, isECDSA := privateKey.(*ecdsa.PrivateKey)
	if isRSA {
		// Sign using RSA-PSS using provided algorithm
		switch hashAlgo {
		case crypto.SHA256:
			pssData := data
			hasher := crypto.SHA256.New()
			hasher.Write(pssData)
			digest = hasher.Sum(nil)
			signature, err = rsa.SignPSS(
				ca.params.Random, rsaPriv, hashAlgo, digest, &pssOpts)
		case crypto.SHA512:
			pssData := data
			hasher := crypto.SHA512.New()
			hasher.Write(pssData)
			digest = hasher.Sum(nil)
			signature, err = rsa.SignPSS(
				ca.params.Random, rsaPriv, hashAlgo, digest, &pssOpts)
		default:
			return nil, nil, fmt.Errorf("%s: %s",
				ErrUnsupportedHashAlgorithm, hashAlgo.String())
		}
	} else if isECDSA {
		digest := []byte{}
		switch hashAlgo {
		case crypto.SHA256:
			pssData := data
			hasher := crypto.SHA256.New()
			hasher.Write(pssData)
			digest = hasher.Sum(nil)
		case crypto.SHA512:
			pssData := data
			hasher := crypto.SHA512.New()
			hasher.Write(pssData)
			digest = hasher.Sum(nil)
		default:
			return nil, nil, fmt.Errorf("%s: %s",
				ErrUnsupportedSigningAlgorithm, hashAlgo.String())
		}
		signature, err = ecdsa.SignASN1(rand.Reader, eccPriv, digest)
	} else {
		return nil, nil, fmt.Errorf("%s: %s",
			ErrUnsupportedSigningAlgorithm, hashAlgo.String())
	}
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, nil, err
	}
	// Save the signature to the blob store if enabled
	if opts != nil {
		if opts.StoreSignature && opts.BlobKey != nil {
			sigKey := fmt.Sprintf("%s%s", *opts.BlobKey, FSEXT_SIG)
			if err := ca.certStore.SaveBlob(sigKey, signature); err != nil {
				return nil, nil, err
			}
		}
		if opts.BlobKey != nil {
			if err := ca.certStore.SaveBlob(*opts.BlobKey, data); err != nil {
				return nil, nil, err
			}
		}
	}
	return signature, digest, nil
}

// Verifies the requested RSA PSS digest.
// Options:
// 1. KeyCN: An optional signing key. Default is CA public key.
// 2. Hash:  An optional cypto.Hash signing algorithm. Default is SHA256.
// 3. UseStoredSignature: Uses opts.KeyCN public key for verification
func (ca *CA) VerifySignature(digest []byte, signature []byte, opts *VerifyOpts) error {
	var err error
	var publicKey crypto.PublicKey
	hashAlgo := crypto.SHA256
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
	if ca.params.Config.DefaultKeyAlgorithm == KEY_ALGO_RSA {
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
	} else if ca.params.Config.DefaultKeyAlgorithm == KEY_ALGO_ECC {
		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			ca.params.Logger.Error(err)
			return err
		}
		eccPub, ok := ca.publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyRSA
		}
		hashed := sha256.Sum256(digest)
		if ok := ecdsa.VerifyASN1(eccPub, hashed[:], signature); !ok {
			return ErrInvalidSignature
		}
	} else {
		return ErrInvalidAlgorithm
	}
	return nil
}

// Signs the requested data using PKCS1v15 padding with an optional hash function.
// Options:
// 1. KeyCN: An optional signing key. Default is CA private key.
// 2. Hash:  An optional cypto.Hash signing algorithm. Default is SHA256.
// 3. BlobCN: The common / canonical name used for blob storage
// 4. SaveSignature: Saves the signature to blob storage
// 5. SaveData: Saves the data to blob storage
// NOTE: This function is only be used for backward compatibility, such as TLS.
// PKCS1v15 is insecure and should not be used for any modern integrity checking.
func (ca *CA) SignPKCS1v15(data []byte, password []byte, opts *SigningOpts) ([]byte, []byte, error) {
	var signature, digest []byte
	var privateKey crypto.PrivateKey
	var err error
	hashAlgo := crypto.SHA256
	if opts != nil {
		if opts.Hash != nil {
			hashAlgo = *opts.Hash
		}
		if opts.KeyCN != nil && opts.KeyName != nil {
			privateKey, err = ca.certStore.PrivKey(
				*opts.KeyCN, *opts.KeyName, password, PARTITION_SIGNING_KEYS)
		}
	} else {
		privateKey, err = ca.certStore.CAPrivKey(password)
	}
	if err != nil {
		return nil, nil, err
	}
	privKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, ErrInvalidPrivateKeyRSA
	}
	switch hashAlgo {
	case crypto.SHA256:
		hash := crypto.SHA256.New()
		hash.Reset()
		bytes := sha256.Sum256(data)
		digest = bytes[:]
		signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, hashAlgo, digest)
		if err != nil {
			ca.params.Logger.Error(err)
			return nil, nil, err
		}
	// TODO: Support other algorithms
	// case crypto.SHA512:
	// 	hash := crypto.SHA512.New()
	// 	hash.Reset()
	// 	bytes := sha512.Sum512(data)
	// 	digest = bytes[:]
	// 	signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, hashAlgo, digest)
	default:
		return nil, nil, fmt.Errorf("%s: %s", ErrUnsupportedSigningAlgorithm, hashAlgo.String())
	}
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, nil, err
	}
	if opts != nil {
		if opts.StoreSignature && opts.BlobKey != nil {
			sigKey := fmt.Sprintf("%s%s", *opts.BlobKey, FSEXT_SIG)
			if err := ca.certStore.SaveBlob(sigKey, signature); err != nil {
				return nil, nil, err
			}
		}
		if opts.BlobKey != nil {
			if err := ca.certStore.SaveBlob(*opts.BlobKey, data); err != nil {
				return nil, nil, err
			}
		}
	}
	return signature, digest, nil
}

// Verifies the requested RSA PKCS1v15 digest.
// Options:
// 1. KeyCN: An optional signing key. Default is CA public key.
// 2. Hash:  An optional cypto.Hash signing algorithm. Default is SHA256.
// 3. UseStoredSignature: Uses opts.KeyCN public key for verification
func (ca *CA) VerifyPKCS1v15(digest, signature []byte, opts *VerifyOpts) error {
	var publicKey crypto.PublicKey
	var err error
	hashAlgo := crypto.SHA256
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
