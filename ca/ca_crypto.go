package ca

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

// Creates a new RSA encryption key for the requested common name and
// returns the public half of the key. Private encryption keys are
// never returned from from the Certificate Authority, and are stored
// in a separate partition / hierarchy for security and to provide
// flexibility to backup, restore, and rotate keyes.
func (ca *CA) NewEncryptionKey(cn, keyName string, password, caPassword []byte) (*rsa.PrivateKey, error) {
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
		cn, keyName, pkcs8, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PKCS8)
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
		cn, keyName, pkcs8PEM, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Public Key: Encode to PKIX, ASN.1 DER form
	pubDER, err := ca.EncodePubKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	// Public Key: Save the ASN.1 DER PKCS1 form
	err = ca.certStore.SaveKeyed(
		cn, keyName, pubDER, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PKCS1)
	if err != nil {
		return nil, err
	}
	// Public Key: Encdode to PEM form
	pubPEM, err := ca.EncodePubKeyPEM(cn, pubDER)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Public Key: Save PEM form
	err = ca.certStore.SaveKeyed(cn, keyName, pubPEM, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	// Sign: sign the public key with the CA public key to make it verifiable
	sigKey := NewSigningKey(ca.params.Logger, ca, caPassword, &privateKey.PublicKey)
	sigOpts, err := NewSigningOpts(ca.Hash(), pubPEM)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	sig, err := sigKey.Sign(ca.params.Random, sigOpts.Digest(), sigOpts)
	if err != nil {
		return nil, err
	}
	// Sign: Save the signature with the keys
	err = ca.certStore.SaveKeyed(cn, keyName, sig, PARTITION_ENCRYPTION_KEYS, FSEXT_SIG)
	if err != nil {
		ca.params.Logger.Error(err)
		return nil, err
	}
	return privateKey, nil
}

// Returns the RSA public key for the requested common name / key from the
// encryption keys partition
func (ca *CA) EncryptionKey(cn, keyName string) (*rsa.PublicKey, error) {
	pubPEM, err := ca.certStore.GetKeyed(
		cn, keyName, PARTITION_ENCRYPTION_KEYS, FSEXT_PUBLIC_PEM)
	if err != nil {
		return nil, err
	}
	rsaPub, err := ca.DecodeRSAPubKeyPEM(pubPEM)
	if err != nil {
		return nil, err
	}
	return rsaPub.(*rsa.PublicKey), nil
}

// Returns a crypto.Decrypter implementation for PKCS #8 private keys
func (ca *CA) DecryptionKey(cn, keyName string, password []byte) (crypto.Decrypter, error) {
	privDER, err := ca.certStore.GetKeyed(
		cn, keyName, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		return nil, err
	}
	privKey, err := ca.ParsePrivateKey(privDER, password)
	if err != nil {
		return nil, err
	}
	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKeyRSA
	}
	return NewPKCS8Decrypter(ca.params.Random, ca.Hash(), ca, rsaPriv), nil
}

// Encrypts the requested data using RSA Optimal Asymetric Encryption
// Padding (OAEP) provided by the common name's public key. OAEP is used
// to protect against Bleichenbacher ciphertext attacks described here:
// https://pkg.go.dev/crypto/rsa#DecryptPKCS1v15SessionKey
// https://www.rfc-editor.org/rfc/rfc3218.html#section-2.3.2
func (ca *CA) RSAEncrypt(cn, keyName string, data []byte) ([]byte, error) {
	pub, err := ca.EncryptionKey(cn, keyName)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), ca.params.Random, pub, data, nil)
}

// Decrypts the requested data, expected with OAEP padding, using the common
// name's RSA private key.
func (ca *CA) RSADecrypt(cn, keyName string, password, ciphertext []byte) ([]byte, error) {
	privDER, err := ca.certStore.GetKeyed(
		cn, keyName, PARTITION_ENCRYPTION_KEYS, FSEXT_PRIVATE_PKCS8)
	if err != nil {
		return nil, err
	}
	priv, err := ca.ParsePrivateKey(privDER, password)
	if err != nil {
		return nil, err
	}
	privKey := priv.(*rsa.PrivateKey)
	return rsa.DecryptOAEP(sha256.New(), ca.params.Random, privKey, ciphertext, nil)
}

// Decrypts a message using the Certificate Authority private key
// Implements crypto.Decrypter
func (ca *CA) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	priv, err := ca.CAPrivKey(ca.params.Password)
	if err != nil {
		ca.params.Logger.Error(priv)
		return nil, err
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKeyRSA
	}
	return rsaPriv.Decrypt(rand, msg, opts)
}
