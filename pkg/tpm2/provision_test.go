package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestProvisionOwner(t *testing.T) {

	logger, tpm := createSim(false, false)
	defer tpm.Close()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	ssrkAttrs, err := tpm.SSRKAttributes()
	assert.Nil(t, err)

	iakAttrs, err := tpm.IAKAttributes()
	assert.Nil(t, err)

	keystore.DebugKeyAttributes(logger, ekAttrs)
	keystore.DebugKeyAttributes(logger, ssrkAttrs)
	keystore.DebugKeyAttributes(logger, iakAttrs)
}

func TestSetHierarchyAuth(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	password := keystore.NewClearPassword([]byte("test"))
	err = tpm.SetHierarchyAuth(hierarchyAuth, password, nil)

	assert.Nil(t, err)
}

func TestGoldenMeasurements(t *testing.T) {

	logger, tpm := createSim(false, false)
	defer tpm.Close()

	goldenPCR := tpm.GoldenMeasurements()
	assert.NotNil(t, goldenPCR)

	logger.Debugf("Golden PCR: 0x%s", Encode(goldenPCR))
}
