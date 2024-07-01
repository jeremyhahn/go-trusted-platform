package ca

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CA_SignAndVerify_RSA_PKCS1v15(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Sign it
	signature, digest, err := rootCA.SignPKCS1v15(data, rootPass, nil)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifyPKCS1v15(digest, signature, nil))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))
}

func Test_CA_SignAndVerify_RSA_PSS(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Sign it
	signature, digest, err := rootCA.Sign(data, rootPass, nil)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifySignature(digest, signature, nil))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))
}

func Test_CA_SignAndVerify_WithStorage(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	signingOpts := &SigningOpts{
		StoreSignature: true,
		BlobKey:        &blobKey,
	}
	verifyOpts := &VerifyOpts{
		UseStoredSignature: false,
	}

	// Sign and store the data and the signature
	signature, digest, err := rootCA.Sign(data, rootPass, signingOpts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)
	assert.NotNil(t, digest)

	storedSignature, err := rootCA.Signature(blobKey)
	assert.Nil(t, err)
	assert.NotNil(t, signature)
	assert.Equal(t, signature, storedSignature)

	// Verify the data with the stored signature
	err = rootCA.VerifySignature(digest, signature, verifyOpts)
	assert.Nil(t, err)

	// Modified data to ensure verification fails
	newData := []byte("injected-malware")
	err = rootCA.VerifySignature(newData, signature, verifyOpts)
	assert.NotNil(t, err)

	// Ensure the check to see if the signature data exists
	signed, err := rootCA.Signed(blobKey)
	assert.Nil(t, err)
	assert.True(t, signed)

	// Ensure the signed data can be retrieved
	signedData, err := rootCA.SignedData(blobKey)
	assert.Nil(t, err)
	assert.Equal(t, data, signedData)
}

func Test_SigningKey_SignAndVerify_RSA_PKCS1v15(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	cn := "test.com"
	keyName := "app1"
	keyPass := []byte("app1-secret")

	// Create new signing key
	key, err := rootCA.NewSigningKey(cn, keyName, keyPass, rootPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign test data
	signature, digest, err := rootCA.SignPKCS1v15(data, rootPass, nil)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifyPKCS1v15(digest, signature, nil))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))
}

func Test_SigningKey_SignAndVerify_RSA_PSS(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	cn := "test.com"
	keyName := "app1"
	keyPass := []byte("app1-secret")

	key, err := rootCA.NewSigningKey(cn, keyName, keyPass, rootPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign it
	signature, digest, err := rootCA.Sign(data, rootPass, nil)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifySignature(digest, signature, nil))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, nil))
}

func Test_SigningKey_SignAndVerify_RSA_PSS_WithStorage(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	keyCN := "test.com"
	keyName := "app1"
	keyPass := []byte("app1-secret")
	signingOpts := &SigningOpts{
		KeyCN:          &keyCN,
		KeyName:        &keyName,
		BlobKey:        &blobKey,
		StoreSignature: true,
	}
	verifyOpts := &VerifyOpts{
		KeyCN:              &keyCN,
		KeyName:            &keyName,
		BlobKey:            &blobKey,
		UseStoredSignature: true,
	}

	key, err := rootCA.NewSigningKey(keyCN, keyName, keyPass, rootPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign it
	signature, digest, err := rootCA.Sign(data, keyPass, signingOpts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = rootCA.VerifySignature(digest, nil, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	err = rootCA.VerifySignature(newData, nil, verifyOpts)
	assert.NotNil(t, err)
}

func Test_SigningKey_SignAndVerify_RSA_PKCS1v15_WithStorage(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Create test data
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	keyCN := "test.com"
	keyName := "app1"
	keyPass := []byte("app1-secret")
	signingOpts := &SigningOpts{
		KeyCN:          &keyCN,
		KeyName:        &keyName,
		BlobKey:        &blobKey,
		StoreSignature: true,
	}
	verifyOpts := &VerifyOpts{
		KeyCN:              &keyCN,
		KeyName:            &keyName,
		BlobKey:            &blobKey,
		UseStoredSignature: true,
	}

	key, err := rootCA.NewSigningKey(keyCN, keyName, keyPass, rootPass)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	// Sign it
	signature, digest, err := rootCA.SignPKCS1v15(data, keyPass, signingOpts)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	err = rootCA.VerifyPKCS1v15(digest, signature, verifyOpts)
	assert.Nil(t, err)

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature, verifyOpts))
}
