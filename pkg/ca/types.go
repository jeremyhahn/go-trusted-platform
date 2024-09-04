package ca

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	ErrInvalidIssuingURL = errors.New("certificate-authority: invalid issuing URL")
	ErrUnsealFailure     = errors.New("certificate-authority: key unseal operation failed")

	ATTEST_BLOB_ROOT     string = "tpm"
	ATTEST_AK_NAME              = "ak"
	ATTEST_BLOB_QUOTE           = "quote"
	ATTEST_BLOB_EVENTLOG        = "eventlog"
	ATTEST_BLOB_PCRS            = "pcrs"
	ATTEST_EK_CERT_NAME         = "ek"
)

type CertificateRequest struct {
	SANS          *SubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject       Subject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid         int                      `yaml:"valid" json:"valid" mapstructure:"valid"`
	KeyAttributes *keystore.KeyAttributes  `yaml:"-" json:"-" mapstructure:"-"`
}

type IDevIDCertificateRequest struct {
	CertificateRequest
	PermanentID string `yaml:"permanent-id" json:"permanent_id" mapstructure:"permanent-id"`
	ProdModel   string `yaml:"prod-model" json:"prod_model" mapstructure:"prod-model"`
	ProdSerial  string `yaml:"prod-serial" json:"prod_serial" mapstructure:"prod-serial"`
}

type OSTrustStore interface {
	Install(cn string) error
	Uninstall(cn string) error
}
