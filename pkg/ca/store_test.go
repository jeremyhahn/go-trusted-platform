package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

var (
	TEST_DATA_DIR       = "./testdata"
	TEST_CN             = "exapmle.com"
	TEST_RETAIN_REVOKED = true

	// https://phpseclib.com/docs/rsa-keys
	// https://fm4dd.com/openssl/certexamples.shtm
	TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy
2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0
Hn+GmxZA
-----END CERTIFICATE-----`
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	// os.RemoveAll(TEST_DATA_DIR)
}

func setup() {
	os.RemoveAll(TEST_DATA_DIR)
}

func TestSaveCA(t *testing.T) {

	cs, tmpDir := createCertStore()
	caAttrs := keystore.Templates[x509.RSA]
	caAttrs.KeyType = keystore.KEY_TYPE_CA
	defer os.RemoveAll(tmpDir)

	data := []byte(TEST_CERT_PEM)
	err := cs.Save(caAttrs, data, store.FSEXT_PEM, nil)
	assert.Nil(t, err)

	expectedPath := fmt.Sprintf(
		"%s/%s.rsa%s",
		tmpDir,
		caAttrs.Domain,
		store.FSEXT_PEM)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func TestSaveTLS(t *testing.T) {

	cs, tmpDir := createCertStore()
	tlsAttrs := keystore.Templates[x509.RSA]
	tlsAttrs.KeyType = keystore.KEY_TYPE_TLS
	tlsAttrs.Domain = "example.com"
	tlsAttrs.CN = "www.example.com"
	defer os.RemoveAll(tmpDir)

	data := []byte(TEST_CERT_PEM)
	err := cs.Save(tlsAttrs, data, store.FSEXT_PRIVATE_PKCS8, nil)
	assert.Nil(t, err)

	expectedPath := fmt.Sprintf(
		"%s/issued/%s/%s.rsa%s",
		tmpDir,
		tlsAttrs.CN,
		tlsAttrs.CN,
		store.FSEXT_PRIVATE_PKCS8)

	path, err := util.FileExists(expectedPath)
	assert.Nil(t, err)
	assert.True(t, path)
}

func createCertStore() (CertificateStorer, string) {
	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("keystore-x509")
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)

	// Create a temp directory for each instantiation
	// so parallel tests don't corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		panic(err)
	}
	tmpDir := hex.EncodeToString(buf)

	caDomain := "example.com"
	tmp := fmt.Sprintf("%s/%s/%s", TEST_DATA_DIR, tmpDir, caDomain)

	cs, err := NewFileSystemCertStore(
		logger,
		store.NewFileBackend(logger, tmp),
		tmp,
		TEST_CN,
		TEST_RETAIN_REVOKED)
	if err != nil {
		logger.Fatal(err)
	}
	return cs, tmp
}
