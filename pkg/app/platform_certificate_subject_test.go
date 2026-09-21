package app

import (
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

func TestPlatformCertificateSubject_FromThePrimaryWebService(t *testing.T) {
	ws := &v1.Config{}
	ws.Certificate.Subject.Organization = "Trusted Platform"
	ws.Certificate.Subject.Country = "US"
	ws.Certificate.Subject.Locality = "Somewhere"
	ws.Certificate.Subject.Address = "1 Main St"
	ws.Certificate.Subject.PostalCode = "00000"

	subject := platformCertificateSubject("ek-cn", ws)

	assert.Equal(t, "ek-cn", subject.CommonName)
	assert.Equal(t, "Trusted Platform", subject.Organization)
	assert.Equal(t, "US", subject.Country)
	assert.Equal(t, "Somewhere", subject.Locality)
	assert.Equal(t, "1 Main St", subject.Address)
	assert.Equal(t, "00000", subject.PostalCode)
}

func TestPlatformCertificateSubject_DaemonOnlyDeploymentHasNoWebService(t *testing.T) {
	subject := platformCertificateSubject("ek-cn", nil)

	assert.Equal(t, "ek-cn", subject.CommonName)
	assert.Empty(t, subject.Organization)
	assert.Empty(t, subject.Country)
}
