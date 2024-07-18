package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

//
// CA Signing key tests
//

// Test RSA signing with PKCS1v15 padding using the CA key
func Test_CA_RSA_PKCS1v15(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Get the CA key attributes
	caKeyAttributes := intermediateCA.CAKeyAttributes(nil)

	// Get the CA's signing key using its key attributes
	caSigner, err := intermediateCA.SigningKey(caKeyAttributes)
	assert.Nil(t, err)
	assert.NotNil(t, caSigner)

	// Create new signing opts to build the digest. The digest
	// could also be built manually, but this method ensures the
	// same hash function used to generate certificates is
	// the same hash function used by the signer and verifier.
	opts, err := keystore.NewSignerOpts(caKeyAttributes, data)
	assert.Nil(t, err)

	// Sign the data using the CA's public key - NOT passing the
	// opts, only using it's digest and hash function
	signature, err := caSigner.Sign(rand.Reader, opts.Digest(), opts.HashFunc())
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify the signature using the CA's signing key
	err = intermediateCA.VerifySignature(opts.Digest(), signature, nil)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, nil))
}

func Test_CA_RSA_PKCS1v15_WithBlobStorage(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobCN := "/my/pkcs1v15/data.txt"
	data := []byte("hello\nworld\n")

	// Get the CA key attributes
	caKeyAttributes := intermediateCA.CAKeyAttributes(nil)

	// Get the CA's signing key using its key attributes
	caSigner, err := intermediateCA.SigningKey(caKeyAttributes)
	assert.Nil(t, err)
	assert.NotNil(t, caSigner)

	// Create new signing opts to build the digest. The digest
	// could also be built manually, but this method ensures the
	// same hash function used to generate certificates is
	// the same hash function used by the signer and verifier.
	opts, err := keystore.NewSignerOpts(caKeyAttributes, data)
	assert.Nil(t, err)

	// Set the blob CN so the signer persists the signature,
	// digest, and a checksum
	opts.BlobCN = &blobCN

	// Set the blob data so the signer persists the blob data
	opts.BlobData = data

	// Sign the data using the CA's public key - NOT passing the
	// opts, only using it's digest and hash function
	signature, err := caSigner.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify the signature using the CA's signing key
	err = intermediateCA.VerifySignature(opts.Digest(), signature, nil)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, nil))
}

func Test_CA_RSA_PSS(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Get the CA key attributes
	caKeyAttributes := intermediateCA.CAKeyAttributes(nil)

	// Get the CA's signing key using its key attributes
	caSigner, err := intermediateCA.SigningKey(caKeyAttributes)
	assert.Nil(t, err)
	assert.NotNil(t, caSigner)

	// Create new signing opts to build the digest. The digest
	// could also be built manually, but this method ensures the
	// same hash function used to generate certificates is
	// the same hash function used by the signer and verifier.
	opts, err := keystore.NewSignerOpts(caKeyAttributes, data)
	assert.Nil(t, err)

	// Create PSS options to pass to the signer
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       opts.HashFunc(),
	}

	// Sign the data using the CA's public key, passing PSS padding opts
	signature, err := caSigner.Sign(rand.Reader, opts.Digest(), pssOpts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Create PSS padding verifier opts
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: caKeyAttributes,
		PSSOptions:    pssOpts,
	}

	// Verify the signature using the CA's signing key with PSS padding opts
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, verifyOpts))
}

func Test_CA_RSA_PSS_WithBlobStorage(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobCN := "/my/pss/data.txt"
	data := []byte("hello\nworld\n")

	// Get the CA key attributes
	caKeyAttributes := intermediateCA.CAKeyAttributes(nil)

	// Get the CA's signing key using its key attributes
	caSigner, err := intermediateCA.SigningKey(caKeyAttributes)
	assert.Nil(t, err)
	assert.NotNil(t, caSigner)

	// Create new signing opts to build the digest. The digest
	// could also be built manually, but this method ensures the
	// same hash function used to generate certificates is
	// the same hash function used by the signer and verifier.
	opts, err := keystore.NewSignerOpts(caKeyAttributes, data)
	assert.Nil(t, err)

	// Create PSS options to pass to the signer
	opts.PSSOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       opts.HashFunc(),
	}

	// Set the blob CN so the signer persists the signature,
	// digest, and a checksum
	opts.BlobCN = &blobCN

	// Set the blob data so the signer persists the blob data
	opts.BlobData = data

	// Sign the data using the CA's public key, passing PSS padding opts
	signature, err := caSigner.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Create PSS padding verifier opts
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: caKeyAttributes,
		PSSOptions:    opts.PSSOptions,
	}

	// Verify the signature using the CA's signing key with PSS padding opts
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, verifyOpts))
}

//
// Dedicated signing key tests
//

// Test RSA dedicated signing key using PKCS1v15 padding scheme
func Test_SigningKey_RSA_PKCS1v15(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, rootCA, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Define key attributes
	attrs := keystore.KeyAttributes{
		// Pass the CA's password for PKCS #8
		AuthPassword:       []byte(rootCA.Identity().KeyPassword),
		Password:           []byte(intermediateCA.Identity().KeyPassword),
		Domain:             "example.com",
		CN:                 "app1",
		KeyType:            keystore.KEY_TYPE_SIGNING,
		Hash:               intermediateCA.Hash(),
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		RSAAttributes: &keystore.RSAAttributes{
			KeySize: 512,
			// KeyScheme: keystore.RSA_SCHEME_RSAPSS,
		},
	}

	// Create the new dedicated signing key
	key, err := intermediateCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Create signing opts using the dedicated signing key
	opts, err := keystore.NewSignerOpts(attrs, data)
	assert.Nil(t, err)

	// Sign the data digest using the dedicated signing key
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Set verifier opts that specify the dedicated signing key
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: attrs,
		// IntegrityCheck: true,
	}

	// Verify the signature using the dedicated signing key
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = intermediateCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)
}

func Test_SigningKey_RSA_PKCS1v15_WithBlobStorage(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, rootCA, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobCN := "/my/pkcs1v15/data.txt"
	data := []byte("hello\nworld\n")

	// Define key attributes
	attrs := keystore.KeyAttributes{
		// Pass the CA's password for PKCS #8
		AuthPassword:       []byte(rootCA.Identity().KeyPassword),
		Password:           []byte(intermediateCA.Identity().KeyPassword),
		Domain:             "example.com",
		CN:                 "app1",
		KeyType:            keystore.KEY_TYPE_SIGNING,
		Hash:               intermediateCA.Hash(),
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		RSAAttributes: &keystore.RSAAttributes{
			KeySize: 512,
			// KeyScheme: keystore.RSA_SCHEME_RSAPSS,
		},
	}

	// Create the new dedicated signing key
	key, err := intermediateCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Create signing opts using the dedicated signing key
	opts, err := keystore.NewSignerOpts(attrs, data)
	assert.Nil(t, err)

	// Set the blob CN so the signer persists the signature,
	// digest, and a checksum
	opts.BlobCN = &blobCN

	// Set the blob data so the signer persists the blob data
	opts.BlobData = data

	// Sign the data digest using the dedicated signing key
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Set verifier opts that specify the dedicated signing key
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: attrs,
		// BlobCN: blobCN,
		// IntegrityCheck: true,
	}

	// Verify the signature using the dedicated signing key
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = intermediateCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)
}

// Test RSA dedicated signing key using PSS padding scheme
func Test_SigningKey_RSA_PSS(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, rootCA, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Define key attributes
	attrs := keystore.KeyAttributes{
		// Pass the CA's password for PKCS #8
		AuthPassword:       []byte(rootCA.Identity().KeyPassword),
		Password:           []byte(intermediateCA.Identity().KeyPassword),
		Domain:             "example.com",
		CN:                 "app1",
		KeyType:            keystore.KEY_TYPE_SIGNING,
		Hash:               intermediateCA.Hash(),
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		RSAAttributes: &keystore.RSAAttributes{
			KeySize: 512,
			// KeyScheme: keystore.RSA_SCHEME_RSAPSS,
		},
	}

	// Create the new dedicated signing key
	key, err := intermediateCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Create signing opts using the dedicated signing key
	opts, err := keystore.NewSignerOpts(attrs, data)
	assert.Nil(t, err)

	// Add PSS options to the signing opts. Use the hash
	// function defined by the dedicated signing key attributes.
	opts.PSSOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       attrs.Hash,
	}

	// Sign the data digest using the dedicated signing key
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Set verifier opts that specify the dedicated signing key
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: attrs,
		PSSOptions:    opts.PSSOptions,
		// IntegrityCheck: true,
	}

	// Verify the signature using the dedicated signing key
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = intermediateCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)
}

// Test RSA dedicated signing key using PSS padding scheme
// with blob storage options
func Test_SigningKey_RSA_PSS_WithBlobStorage(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, rootCA, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobCN := "/my/pss/data.txt"
	data := []byte("hello\nworld\n")

	// Define key attributes
	attrs := keystore.KeyAttributes{
		// Pass the CA's password for PKCS #8
		AuthPassword:       []byte(rootCA.Identity().KeyPassword),
		Password:           []byte(intermediateCA.Identity().KeyPassword),
		Domain:             "example.com",
		CN:                 "app1",
		KeyType:            keystore.KEY_TYPE_SIGNING,
		Hash:               intermediateCA.Hash(),
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		RSAAttributes: &keystore.RSAAttributes{
			KeySize: 512,
			// KeyScheme: keystore.RSA_SCHEME_RSAPSS,
		},
	}

	// Create the new dedicated signing key
	key, err := intermediateCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Create signing opts using the dedicated signing key
	opts, err := keystore.NewSignerOpts(attrs, data)
	assert.Nil(t, err)

	// Add PSS options to the signing opts. Use the hash
	// function defined by the dedicated signing key attributes.
	opts.PSSOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       attrs.Hash,
	}

	// Set the blob CN so the signer persists the signature,
	// digest, and a checksum
	opts.BlobCN = &blobCN

	// Set the blob data so the signer persists the blob data
	opts.BlobData = data

	// Sign the data digest using the dedicated signing key
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Set verifier opts that specify the dedicated signing key
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes:  attrs,
		PSSOptions:     opts.PSSOptions,
		BlobCN:         blobCN,
		IntegrityCheck: true,
	}

	// Verify the signature using the dedicated signing key
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = intermediateCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)
}

func Test_SigningKey_ECDSA(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.ECDSA.String()
	config.EllipticalCurve = string(keystore.CURVE_P256)
	config.SignatureAlgorithm = x509.ECDSAWithSHA256.String()

	_, rootCA, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Create new key attributes using key store template
	attrs, err := keystore.Template(x509.ECDSA)
	attrs.KeyType = keystore.KEY_TYPE_SIGNING
	assert.Nil(t, err)

	// Set new signing key specific properties
	attrs.AuthPassword = []byte(rootCA.Identity().KeyPassword)
	attrs.Domain = "test.com"
	attrs.CN = "app1"
	attrs.Password = []byte("app1-secret")

	// Create signing options
	opts, err := keystore.NewSignerOpts(attrs, data)
	assert.Nil(t, err)

	// Set the signing options key attributes
	opts.KeyAttributes = attrs

	// Set the key attributes for verification
	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes: attrs,
	}

	// Create new ECDSA signing key
	sigKey, err := intermediateCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, sigKey)

	// Sign the digest
	signature, err := sigKey.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify the signature
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, nil))
}

func Test_SigningKey_ECDSA_WithStorage(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.ECDSA.String()
	config.SignatureAlgorithm = x509.ECDSAWithSHA256.String()

	_, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Define key attributes
	attrs := intermediateCA.CAKeyAttributes(nil)
	attrs.Domain = "test.com"
	attrs.CN = "app1"
	attrs.Password = []byte("app1-secret")
	attrs.KeyType = keystore.KEY_TYPE_SIGNING

	// Define test data and storage path
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	// Create signing options
	opts, err := keystore.NewSignerOpts(attrs, data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyAttributes = attrs
	opts.BlobCN = &blobKey
	opts.BlobData = data

	verifyOpts := &keystore.VerifyOpts{
		KeyAttributes:  attrs,
		BlobCN:         blobKey,
		IntegrityCheck: true,
	}

	sigKey, err := intermediateCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, sigKey)

	// Sign it
	signature, err := sigKey.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, nil))

	// Ensure the signed blob was persisted to blob storage
	// and the CA is able to retrieve it
	blob, err := intermediateCA.Blob(blobKey)
	assert.Nil(t, err)
	assert.True(t, len(blob) == 12)
}

func TestGetSigningKey(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.DefaultKeyAlgorithm = x509.RSA.String()
	// config.RSAScheme = string(keystore.RSA_SCHEME_RSAPSS)
	config.SignatureAlgorithm = x509.SHA256WithRSA.String()

	_, rootCA, _, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Define key attributes
	attrs := keystore.TemplateRSA
	attrs.Domain = "test.com"
	attrs.CN = "app1"
	attrs.Password = []byte("app1-secret")
	attrs.AuthPassword = []byte(rootCA.Identity().KeyPassword)

	// Create new signing key
	key, err := rootCA.NewSigningKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Retrieve the key from the store
	_, err = rootCA.SigningKey(attrs)
	assert.Nil(t, err)
}
