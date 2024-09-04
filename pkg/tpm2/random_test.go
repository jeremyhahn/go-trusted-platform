package tpm2

import (
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
)

func TestRandBytes(t *testing.T) {

	_, tpm := createSim(false, true)
	defer tpm.Close()

	randomBytes := make([]byte, 32)

	n, err := tpm.Read(randomBytes)
	assert.Nil(t, err)
	assert.Equal(t, 32, n)
	assert.Equal(t, len(randomBytes), 32)
}

func TestRandBytesEncrypted(t *testing.T) {

	_, tpm := createSim(true, true)
	defer tpm.Close()

	randomBytes := make([]byte, 32)

	n, err := tpm.Read(randomBytes)
	assert.Nil(t, err)
	assert.Equal(t, 32, n)
	assert.Equal(t, len(randomBytes), 32)
}

func TestRandom(t *testing.T) {

	logger := util.Logger()

	_, tpm := createSim(false, false)
	defer tpm.Close()

	random, err := tpm.Random()
	assert.Nil(t, err)
	assert.NotNil(t, random)
	assert.Equal(t, 32, len(random))

	encoded := hex.EncodeToString(random)

	logger.Debugf("%+s", encoded)
}
