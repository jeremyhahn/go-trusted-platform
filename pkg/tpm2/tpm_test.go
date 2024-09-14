package tpm2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Create a fake TPM cert
// https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
// https://github.com/osresearch/safeboot/pull/85

/*
// Verify CA chain:

	openssl verify \
	  -CAfile testdata/root-ca/root-ca.crt \
	  testdata/intermediate-ca/intermediate-ca.crt

// Verify CA chain & server certificate:

	openssl verify \
	 -CAfile testdata/intermediate-ca/trusted-root/root-ca.crt \
	 -untrusted testdata/intermediate-ca/intermediate-ca.crt \
	 testdata/intermediate-ca/issued/localhost/localhost.crt

// Verify EK chain & certificate:

	openssl verify \
	 -CAfile testdata/intermediate-ca/trusted-root/www.intel.com.crt \
	 -untrusted testdata/intermediate-ca/trusted-intermediate/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.crt \
	 testdata/intermediate-ca/issued/tpm-ek/tpm-ek.crt
*/

func TestInfo(t *testing.T) {

	_, tpm := createSim(false, false)
	defer tpm.Close()

	props, err := tpm.FixedProperties()
	assert.Nil(t, err)
	assert.NotNil(t, props.Manufacturer)
	assert.NotNil(t, props.VendorID)
	assert.NotNil(t, props.Family)
	assert.NotNil(t, props.FwMajor)
	assert.NotNil(t, props.FwMinor)

	fmt.Println(props)
}
