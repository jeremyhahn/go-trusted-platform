package tpm2

import (
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/logger"
	"github.com/stretchr/testify/assert"
)

func TestReadPCRs_TPM(t *testing.T) {

	// if !REAL_TPM_TESTS {
	// 	return
	// }

	_, tpm := createSim(false, false)
	defer tpm.Close()

	pcrs := []uint{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	banks, err := tpm.ReadPCRs(pcrs)
	assert.Nil(t, err)
	assert.NotNil(t, banks)

	for _, bank := range banks {
		for _, pcr := range bank.PCRs {
			fmt.Printf("%s %d: 0x%s\n",
				bank.Algorithm, pcr.ID, string(pcr.Value))
		}
	}

	assert.True(t, len(banks) >= 2)
	assert.Equal(t, 23, len(banks[0].PCRs)) // SHA1
	assert.Equal(t, 23, len(banks[1].PCRs)) // SHA256
}

// NOTE: The user account running the test requires read permissions
// to binary_bios_measurements:
// sudo chown root.myuser /sys/kernel/security/tpm0/binary_bios_measurements
func TestParseEventLog(t *testing.T) {
	// if !REAL_TPM_TESTS {
	// 	return
	// }
	logger, tpm := createSim(false, false)
	defer tpm.Close()

	eventLog, err := tpm.EventLog()
	assert.Nil(t, err)
	assert.NotNil(t, eventLog)

	logger.Debugf("%d", eventLog)
}

func TestQuote(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	nonce := []byte("nonce")

	// Quote with a nonce
	pcrs := []uint{0, 1, 2, 3}
	quote, err := tpm.Quote(pcrs, nonce)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	// Quote without a nonce
	quote, err = tpm.Quote(pcrs, nil)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	pcrs = []uint{0, 1, 2, 3, 5, 6, 7, 8, 9}
	quote, err = tpm.Quote(pcrs, nonce)
	// The simulator doesn't seem to support quoting more than 4 pcrs ??
	// TPM_RC_SIZE (parameter 3): structure is the wrong size
	errStructureWrongSize := tpm2.TPMRC(0x3d5)
	assert.Equal(t, errStructureWrongSize, err)
}

func TestReadPCRs_SIM(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	pcrs := []uint{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	banks, err := tpm.ReadPCRs(pcrs)
	assert.Nil(t, err)
	assert.NotNil(t, banks)

	for _, bank := range banks {
		for _, pcr := range bank.PCRs {
			logger.Infof("%s %d: 0x%s",
				bank.Algorithm, pcr.ID, string(pcr.Value))
		}
	}

	assert.Equal(t, 4, len(banks))
	assert.Equal(t, 23, len(banks[0].PCRs)) // SHA1
	assert.Equal(t, 23, len(banks[1].PCRs)) // SHA256
	assert.Equal(t, 23, len(banks[2].PCRs)) // SHA386
	assert.Equal(t, 23, len(banks[3].PCRs)) // SHA512
}

func TestMakeActivateCredentialWithGeneratedSecret(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	iakAttrs, err := tpm.IAKAttributes()
	assert.Nil(t, err)

	credentialBlob, secret, digest, err := tpm.MakeCredential(
		iakAttrs.TPMAttributes.Name, nil)
	assert.Nil(t, err)
	assert.NotNil(t, credentialBlob)
	assert.NotNil(t, secret)
	assert.NotNil(t, digest)

	// Make sure valid credential passes
	digest, err = tpm.ActivateCredential(credentialBlob, secret)
	assert.Nil(t, err)

	// ... and invalid credential secret fails
	digest, err = tpm.ActivateCredential(credentialBlob, []byte("foo"))
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidActivationCredential, err)
	assert.NotEqual(t, secret, digest)
}

func TestMakeActivateCredential(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	iakAttrs, err := tpm.IAKAttributes()
	assert.Nil(t, err)

	secret := []byte("secret")

	credentialBlob, secret, digest, err := tpm.MakeCredential(
		iakAttrs.TPMAttributes.Name, secret)
	assert.Nil(t, err)
	assert.NotNil(t, credentialBlob)
	assert.NotNil(t, secret)
	assert.NotNil(t, digest)

	// Make sure valid credential passes
	digest, err = tpm.ActivateCredential(credentialBlob, secret)
	assert.Nil(t, err)

	// ... and invalid credential secret fails
	digest, err = tpm.ActivateCredential(credentialBlob, []byte("foo"))
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidActivationCredential, err)
	assert.NotEqual(t, secret, digest)
}
