package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeQuote(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	nonce := []byte("nonce")

	pcrs := []uint{0, 1, 2, 3}
	quote, err := tpm.Quote(pcrs, nonce)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	encoded, err := EncodeQuote(quote)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)

	decoded, err := DecodeQuote(encoded)
	assert.Nil(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, quote, decoded)
}

func TestEncodeDecodePCRBanks(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	pcrs := []uint{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	banks, err := tpm.ReadPCRs(pcrs)
	assert.Nil(t, err)
	assert.NotNil(t, banks)

	encoded, err := EncodePCRs(banks)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)

	decoded, err := DecodePCRs(encoded)
	assert.Nil(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, banks, decoded)
}
