package pkcs11

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPKCS11(t *testing.T) {

	pkcs11, err := NewPKCS11(createConfig())
	assert.Nil(t, err)
	assert.NotNil(t, pkcs11)
}

func createConfig() Config {

	conf := "../../configs/softhsm.conf"
	lib := "/usr/local/lib/softhsm/libsofthsm2.so"

	// err = os.Setenv("SOFTHSM2_CONF", conf)
	// if err != nil {
	// 	return config, err
	// }

	return Config{
		ConfigFile: conf,
		Library:    lib,
	}
}
