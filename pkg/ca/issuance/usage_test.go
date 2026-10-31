package issuance

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyUsages(t *testing.T) {
	cases := map[string]struct {
		names []string
		want  x509.KeyUsage
	}{
		"none":            {nil, 0},
		"canonical":       {[]string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"}, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		"compact lower":   {[]string{"certsign", "crlsign"}, x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
		"content":         {[]string{"Content_Commitment"}, x509.KeyUsageContentCommitment},
		"data and agree":  {[]string{"DATAENCIPHERMENT", "KEY_AGREEMENT"}, x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement},
		"encipher only":   {[]string{"ENCIPHER_ONLY"}, x509.KeyUsageEncipherOnly},
		"decipher only":   {[]string{"DECIPHERONLY"}, x509.KeyUsageDecipherOnly},
		"repeated name":   {[]string{"CERT_SIGN", "CERTSIGN"}, x509.KeyUsageCertSign},
		"every usage bit": {[]string{"DIGITAL_SIGNATURE", "CONTENT_COMMITMENT", "KEY_ENCIPHERMENT", "DATA_ENCIPHERMENT", "KEY_AGREEMENT", "CERT_SIGN", "CRL_SIGN", "ENCIPHER_ONLY", "DECIPHER_ONLY"}, 0x1ff},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParseKeyUsages(tc.names)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseKeyUsages_RefusesUnknownNames(t *testing.T) {
	for _, bad := range []string{"IPSEC_IKE", "NOT_A_USAGE", ""} {
		got, err := ParseKeyUsages([]string{"DIGITAL_SIGNATURE", bad})
		assert.True(t, errors.Is(err, ErrUnsupportedUsage{}), "%q must be refused", bad)
		assert.True(t, IsInvalidRequest(err), "%q is the caller's error", bad)
		assert.Contains(t, err.Error(), `"`+bad+`"`)
		assert.Zero(t, got)
	}
}

func TestParseExtKeyUsages(t *testing.T) {
	cases := map[string]struct {
		names []string
		want  []x509.ExtKeyUsage
	}{
		"none":         {nil, nil},
		"any":          {[]string{"any"}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		"auth":         {[]string{"SERVER_AUTH", "clientauth"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
		"code, email":  {[]string{"CODESIGNING", "EMAIL_PROTECTION"}, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection}},
		"time, ocsp":   {[]string{"TIME_STAMPING", "OCSPSIGNING"}, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning}},
		"compact time": {[]string{"TIMESTAMPING", "OCSP_SIGNING"}, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParseExtKeyUsages(tc.names)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseExtKeyUsages_RefusesUnknownNames(t *testing.T) {
	for _, bad := range []string{"IPSEC_IKE", "NOT_A_USAGE", "IPSEC_TUNNEL"} {
		got, err := ParseExtKeyUsages([]string{"SERVER_AUTH", bad})
		assert.True(t, errors.Is(err, ErrUnsupportedUsage{}), "%q must be refused", bad)
		assert.True(t, IsInvalidRequest(err), "%q is the caller's error", bad)
		assert.Nil(t, got)
	}
}

// An isCA request carrying any extended key usage name, recognized or not,
// is refused before conversion: the CA profile would drop the restriction.
func TestParseRequestUsages_RefusesAnyEKUOnACA(t *testing.T) {
	for _, names := range [][]string{{"IPSEC_IKE"}, {"SERVER_AUTH"}} {
		_, _, _, err := ParseRequestUsages(true, nil, names)
		assert.ErrorIs(t, err, ErrCAExtKeyUsageUnsupported{}, "%v", names)
	}
}

func TestParseRequestUsages(t *testing.T) {
	keyUsage, extKeyUsage, extensions, err := ParseRequestUsages(false, []string{"DIGITAL_SIGNATURE"}, []string{"CLIENT_AUTH"})
	require.NoError(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature, keyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, extKeyUsage)
	assert.Empty(t, extensions, "a plain client certificate carries no installer marker")

	keyUsage, extKeyUsage, extensions, err = ParseRequestUsages(true, []string{"CERT_SIGN", "CRL_SIGN", "DIGITAL_SIGNATURE"}, nil)
	require.NoError(t, err)
	assert.Equal(t, caProfileKeyUsage, keyUsage)
	assert.Nil(t, extKeyUsage)
	assert.Empty(t, extensions)
}

// A leaf request naming PXE_INSTALLER, in either spelling and case, is signed
// with the installer marker extension and id-kp-clientAuth (#1362).
func TestParseRequestUsages_PXEInstallerAddsTheMarkerExtension(t *testing.T) {
	marker, err := InstallerMarkerExtension()
	require.NoError(t, err)
	for _, names := range [][]string{{"PXE_INSTALLER"}, {"pxeinstaller"}, {"CLIENT_AUTH", "pxe_installer"}} {
		keyUsage, extKeyUsage, extensions, err := ParseRequestUsages(false, []string{"DIGITAL_SIGNATURE"}, names)
		require.NoError(t, err, "%v", names)
		assert.Equal(t, x509.KeyUsageDigitalSignature, keyUsage)
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, extKeyUsage, "%v", names)
		assert.Equal(t, []pkix.Extension{marker}, extensions, "%v", names)
	}
}

// The installer marker extension carries only id-kp-clientAuth beside the
// marker, so another usage named with PXE_INSTALLER is refused, not dropped;
// an isCA request naming it is refused like any extended key usage on a CA.
func TestParseRequestUsages_PXEInstallerRefusals(t *testing.T) {
	_, _, _, err := ParseRequestUsages(false, nil, []string{"PXE_INSTALLER", "SERVER_AUTH"})
	assert.ErrorIs(t, err, ErrInstallerExtKeyUsage{})
	assert.Contains(t, err.Error(), "SERVER_AUTH")
	assert.True(t, IsInvalidRequest(err))

	_, _, _, err = ParseRequestUsages(false, nil, []string{"PXE_INSTALLER", "IPSEC_IKE"})
	assert.ErrorIs(t, err, ErrUnsupportedUsage{}, "an unknown name beside PXE_INSTALLER is still refused")

	_, _, _, err = ParseRequestUsages(true, nil, []string{"PXE_INSTALLER"})
	assert.ErrorIs(t, err, ErrCAExtKeyUsageUnsupported{})
}

func TestParseRequestUsages_RefusesUnknownNames(t *testing.T) {
	_, _, _, err := ParseRequestUsages(true, []string{"SIGN_EVERYTHING"}, nil)
	assert.ErrorIs(t, err, ErrUnsupportedUsage{}, "an unknown key usage on a CA must not fall back to the profile")

	_, _, _, err = ParseRequestUsages(false, nil, []string{"IPSEC_IKE"})
	assert.ErrorIs(t, err, ErrUnsupportedUsage{})
}
