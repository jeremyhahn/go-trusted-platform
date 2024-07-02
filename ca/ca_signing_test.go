package ca

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/util"
	"github.com/stretchr/testify/assert"
)

// Test RSA-PSS signing using the CA key
func Test_CA_RSA_PSS(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_RSA
	config.RSAScheme = RSA_SCHEME_RSAPSS
	config.SignatureAlgorithm = "SHA256WithRSA"

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	cn := "test"
	keyName := "app1"
	data := []byte("hello\nworld\n")

	sigKey, err := intermediateCA.NewRSASigningKey(cn, keyName, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, sigKey)

	opts, err := NewSigningOpts(intermediateCA.Hash(), data)
	assert.Nil(t, err)

	// Sign it
	signature, err := sigKey.Sign(rand.Reader, data, opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = intermediateCA.VerifySignature(opts.Digest(), signature, nil)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, intermediateCA.VerifySignature(newData, signature, nil))
}

// Test RSA-PSS with storage: store the digest and signature, verify
// using stored key with specified signature
func Test_SigningKey_RSA_PSS(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_RSA
	config.RSAScheme = RSA_SCHEME_RSAPSS
	config.SignatureAlgorithm = "SHA256WithRSA"

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	keyCN := "test"
	keyName := "app1"
	keyPass := []byte("app1-password")
	data := []byte("hello\nworld\n")

	// Create signing options
	opts, err := NewSigningOpts(intermediateCA.Hash(), data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyCN = &keyCN
	opts.KeyName = &keyName

	verifyOpts := &VerifyOpts{
		KeyCN:   &keyCN,
		KeyName: &keyName,
	}

	key, err := intermediateCA.NewRSASigningKey(keyCN, keyName, keyPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign it
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = intermediateCA.VerifySignature(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = intermediateCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)
}

// Test RSA-PSS with storage: store the digest and signature, verify
// using stored signature.
func Test_SigningKey_RSA_PSS_WithStorage(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_RSA
	config.RSAScheme = RSA_SCHEME_RSAPSS
	config.SignatureAlgorithm = "SHA256WithRSA"

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobKey := "/my/other/secret/data.dat"
	data := []byte("hello\nworld\n")

	keyCN := "test.com"
	keyName := "app1"
	keyPass := []byte("app1-secret")

	// Create signing options
	opts, err := NewSigningOpts(intermediateCA.Hash(), data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyCN = &keyCN
	opts.KeyName = &keyName
	opts.BlobKey = &blobKey
	opts.BlobData = data
	opts.StoreSignature = true

	verifyOpts := &VerifyOpts{
		KeyCN:              &keyCN,
		KeyName:            &keyName,
		BlobKey:            &blobKey,
		UseStoredSignature: true,
	}

	key, err := intermediateCA.NewRSASigningKey(keyCN, keyName, keyPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign it
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = intermediateCA.VerifySignature(opts.Digest(), nil, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = intermediateCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)

	// Ensure the blob exists
	blobPath := fmt.Sprintf("%s/intermediate-ca/blobs/%s", config.Home, blobKey)
	exists, err := util.FileExists(blobPath)
	assert.Nil(t, err)
	assert.True(t, exists)
}

func Test_SigningKey_ECDSA(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_ECC

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	keyCN := "test"
	keyName := "app1"
	keyPass := []byte("app1-password")
	data := []byte("hello\nworld\n")

	// Create signing options
	opts, err := NewSigningOpts(intermediateCA.Hash(), data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyCN = &keyCN
	opts.KeyName = &keyName

	// Set the key to use for verification
	verifyOpts := &VerifyOpts{
		KeyCN:   &keyCN,
		KeyName: &keyName,
	}

	// Create new ECDSA signing key
	sigKey, err := intermediateCA.NewECDSASigningKey(keyCN, keyName, keyPass)
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

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_ECC

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	keyCN := "test"
	keyName := "app1"
	keyPass := []byte("app1-password")
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	// Create signing options
	opts, err := NewSigningOpts(intermediateCA.Hash(), data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyCN = &keyCN
	opts.KeyName = &keyName
	opts.BlobKey = &blobKey
	opts.BlobData = data
	opts.StoreSignature = true

	verifyOpts := &VerifyOpts{
		KeyCN:              &keyCN,
		KeyName:            &keyName,
		BlobKey:            &blobKey,
		UseStoredSignature: true,
	}

	sigKey, err := intermediateCA.NewECDSASigningKey(keyCN, keyName, keyPass)
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

	// Ensure the blob exists
	blobPath := fmt.Sprintf("%s/intermediate-ca/blobs/%s", config.Home, blobKey)
	exists, err := util.FileExists(blobPath)
	assert.Nil(t, err)
	assert.True(t, exists)
}

func Test_CA_SignAndVerify_RSA_PKCS1v15(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_RSA
	config.RSAScheme = RSA_SCHEME_PKCS1v15
	config.SignatureAlgorithm = "SHA256WithRSA"

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	keyCN := "test"
	keyName := "app1"
	data := []byte("hello\nworld\n")

	sigKey, err := rootCA.NewPKCS1v15SigningKey(keyCN, keyName, rootPass)
	assert.Nil(t, err)
	assert.NotNil(t, sigKey)

	// Create signing options
	opts, err := NewSigningOpts(rootCA.Hash(), data)
	assert.Nil(t, err)

	// Sign it
	signature, err := sigKey.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifyPKCS1v15(opts.Digest(), signature, nil))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))
}

func Test_SigningKey_SignAndVerify_RSA_PKCS1v15(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_RSA
	config.RSAScheme = RSA_SCHEME_PKCS1v15
	config.SignatureAlgorithm = "SHA256WithRSA"

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	keyCN := "test"
	keyName := "app1"
	keyPass := []byte("app1-password")
	data := []byte("hello\nworld\n")

	// Create signing options
	opts, err := NewSigningOpts(rootCA.Hash(), data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyCN = &keyCN
	opts.KeyName = &keyName

	verifyOpts := &VerifyOpts{
		KeyCN:   &keyCN,
		KeyName: &keyName,
	}

	// Create new signing key
	key, err := rootCA.NewPKCS1v15SigningKey(keyCN, keyName, keyPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign test data
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = rootCA.VerifyPKCS1v15(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))
}

func Test_SigningKey_SignAndVerify_RSA_PKCS1v15_WithStorage(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	config.KeyAlgorithm = KEY_ALGO_RSA
	config.RSAScheme = RSA_SCHEME_PKCS1v15
	config.SignatureAlgorithm = "SHA256WithRSA"

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	keyCN := "test"
	keyName := "app1"
	keyPass := []byte("app1-password")
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	// Create signing options
	opts, err := NewSigningOpts(rootCA.Hash(), data)
	assert.Nil(t, err)

	// Set storage properties
	opts.KeyCN = &keyCN
	opts.KeyName = &keyName
	opts.BlobKey = &blobKey
	opts.BlobData = data
	opts.StoreSignature = true

	verifyOpts := &VerifyOpts{
		KeyCN:              &keyCN,
		KeyName:            &keyName,
		BlobKey:            &blobKey,
		UseStoredSignature: true,
	}

	// Create new signing key
	key, err := rootCA.NewPKCS1v15SigningKey(keyCN, keyName, keyPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign test data
	signature, err := key.Sign(rand.Reader, opts.Digest(), opts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = rootCA.VerifyPKCS1v15(opts.Digest(), signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))

	// 	// Ensure the blob exists
	blobPath := fmt.Sprintf("%s/root-ca/blobs/%s", config.Home, blobKey)
	exists, err := util.FileExists(blobPath)
	assert.Nil(t, err)
	assert.True(t, exists)
}

func TestGetSigningKey(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	keyCN := "test"
	keyName := "app1"
	keyPass := []byte("app1-password")

	// Create new signing key
	key, err := rootCA.NewPKCS1v15SigningKey(keyCN, keyName, keyPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Retrieve the key from the store
	sigKey, err := rootCA.SigningKey(keyCN, keyName, keyPass)
	assert.Nil(t, err)
	assert.Equal(t, keyPass, sigKey.password)
}
