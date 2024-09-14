package pkcs11

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

var TEST_SOFTHSM_CONF = []byte(`
# SoftHSM v2 configuration file

directories.tokendir = testdata/
objectstore.backend = file
objectstore.umask = 0077

# ERROR, WARNING, INFO, DEBUG
log.level = DEBUG

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
`)

var (
	TEST_DATA_DIR  = "./testdata"
	CLEAN_TMP      = true
	REAL_TPM_TESTS = false
	CACHED_TPM     tpm2.TrustedPlatformModule
	CACHED_DIR     = ""
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
}

func setup() {
	os.RemoveAll(TEST_DATA_DIR)
}

func TestInitHSM(t *testing.T) {

	logger, pkcs11 := createKeystoreSoftHSM2()

	info, err := pkcs11.ctx.GetInfo()
	if err != nil {
		logger.Fatal(err)
	}

	assert.Equal(t, "SoftHSM", info.ManufacturerID)

	util.Logger().Debug(info)
}

func createKeystoreSoftHSM2() (*logging.Logger, *PKCS11) {

	logger := util.Logger()

	if err := os.MkdirAll(TEST_DATA_DIR, fs.ModePerm); err != nil {
		logger.Fatal(err)
	}

	softhsm_conf := fmt.Sprintf("%s/softhsm.conf", TEST_DATA_DIR)
	err := os.WriteFile(softhsm_conf, TEST_SOFTHSM_CONF, fs.ModePerm)
	if err != nil {
		logger.Fatal(err)
	}

	os.Setenv("SOFTHSM2_CONF", softhsm_conf)

	var slot int = 0
	config := &Config{
		Library:       "/usr/local/lib/softhsm/libsofthsm2.so",
		LibraryConfig: softhsm_conf,
		Slot:          &slot,
		// Pin:           "123456",
		// TokenLabel:    "Trusted Platform",
		SOPin: "123456",
		Pin:   "123456",
	}
	pkcs11, err := NewPKCS11(logger, config)
	if err != nil {
		if strings.Contains(err.Error(), "CKR_GENERAL_ERROR") {
			InitSoftHSM(logger, config)
			pkcs11, err = NewPKCS11(logger, config)
			if err != nil {
				logger.Fatal(err)
			}
			// err = pkcs11.ctx.InitToken(0, "123456", "test")
			// if err != nil {
			// 	logger.Fatal(err)
			// }
			// err = pkcs11.ctx.InitToken(1, "123456", "test")
			// if err != nil {
			// 	logger.Fatal(err)
			// }
			// err = pkcs11.ctx.InitToken(2, "123456", "test")
			// if err != nil {
			// 	logger.Fatal(err)
			// }
		}
	}
	return logger, pkcs11
}

// func getYubikey(PIN, PUK string) (*ykpiv.Yubikey, func() error, error) {
// 	yk, err := ykpiv.New(ykpiv.Options{
// 		Reader:             yubikeyReaderName,
// 		PIN:                &PIN,
// 		PUK:                &PUK,
// 		ManagementKeyIsPIN: false,
// 		ManagementKey: []byte{
// 			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
// 		},
// 	})
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	return yk, yk.Close, nil
// }

// func wipeYubikey() error {
// 	yubikey, closer, err := getYubikey("654321", "87654321")
// 	if err != nil {
// 		return err
// 	}
// 	defer closer()

// 	retries, err := yubikey.PINRetries()
// 	if err != nil {
// 		return err
// 	}
// 	for i := 0; i < retries; i++ {
// 		yubikey.Login()
// 	}

// 	retries, _ = yubikey.PINRetries()
// 	if retries != 0 {
// 		return fmt.Errorf("Error wiping Yubikey")
// 	}

// 	yubikey.ChangePUK("87654321")
// 	yubikey.ChangePUK("87654321")
// 	yubikey.ChangePUK("87654321")

// 	return yubikey.Reset()
// }

// var yubikeyReaderName = "Yubikey"
// var defaultPIN = "123456"
// var defaultPUK = "12345678"
// var allSlots = []ykpiv.SlotId{
// 	ykpiv.Authentication,
// 	ykpiv.Signature,
// 	ykpiv.KeyManagement,
// 	ykpiv.CardAuthentication,
// }

// // func TestInitYubiReset(t *testing.T) {
// // 	// if err := wipeYubikey(); err != nil {
// // 	// 	log.Fatal(err)
// // 	// }

// // 	logger := util.Logger()

// // 	yubikey, closer, err := getYubikey("654321", "87654321")
// // 	if err != nil {
// // 		logger.Fatal(err)
// // 	}
// // 	defer closer()
// // 	logger.Info(yubikey.Serial())
// // }

// func TestInitYubiKey(t *testing.T) {

// 	logger, yubi0 := createKeystoreYubiKey(0)
// 	logger.Debug(yubi0.ctx.GetInfo())

// 	_, yubi1 := createKeystoreYubiKey2(0)
// 	logger.Debug(yubi1.ctx.GetInfo())

// }

// func TestKeystoreOpenSC(t *testing.T) {

// 	logger, opensc := createKeystoreOpenSC(0)
// 	logger.Debug(opensc.ctx.GetInfo())
// }

// func TestInitTPM(t *testing.T) {

// 	logger, pkcs11 := createKeystoreTPM()

// 	info, err := pkcs11.ctx.GetInfo()
// 	if err != nil {
// 		logger.Fatal(err)
// 	}

// 	// assert.Equal(t, "Intel", info.ManufacturerID)

// 	util.Logger().Debug(info)

// }

// func createKeystoreOpenSC(slot int) (*logging.Logger, *PKCS11) {

// 	logger := util.Logger()

// 	config := &Config{
// 		Library:    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
// 		Slot:       &slot,
// 		SOPin:      "12345678",
// 		Pin:        "123456",
// 		TokenLabel: "YubiKey PIV #12345678",
// 	}
// 	pkcs11, err := NewPKCS11(logger, config)
// 	if err != nil {
// 		logger.Fatal(err)
// 	}
// 	return logger, pkcs11
// }

// func createKeystoreYubiKey(slot int) (*logging.Logger, *PKCS11) {

// 	logger := util.Logger()

// 	config := &Config{
// 		Library:    "/usr/local/lib/libykcs11.so.2.5.2",
// 		Slot:       &slot,
// 		SOPin:      "12345678",
// 		Pin:        "123456",
// 		TokenLabel: "YubiKey PIV #12345678",
// 	}
// 	pkcs11, err := NewPKCS11(logger, config)
// 	if err != nil {
// 		logger.Fatal(err)
// 	}
// 	return logger, pkcs11
// }

// func createKeystoreYubiKey2(slot int) (*logging.Logger, *PKCS11) {

// 	logger := util.Logger()

// 	config := &Config{
// 		Library:    "/usr/local/lib/libykcs11.so.2.5.2",
// 		Slot:       &slot,
// 		SOPin:      "12345678",
// 		Pin:        "123456",
// 		TokenLabel: "YubiKey PIV #23456789",
// 	}
// 	pkcs11, err := NewPKCS11(logger, config)
// 	if err != nil {
// 		logger.Fatal(err)
// 	}
// 	return logger, pkcs11
// }

// func createKeystoreTPM() (*logging.Logger, *PKCS11) {

// 	logger := util.Logger()

// 	var slot int = 0
// 	config := &Config{
// 		Library: "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so",
// 		Slot:    &slot,
// 	}
// 	pkcs11, err := NewPKCS11(logger, config)
// 	if err != nil {
// 		logger.Fatal(err)
// 	}
// 	return logger, pkcs11
// }

func cleanTempDir(dir string) {
	if CLEAN_TMP {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Errorf("%S", err)
		}
	}
}
