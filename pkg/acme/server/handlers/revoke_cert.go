package handlers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

// Revocation statuses (for /revoke-cert)
const (
	RevocationReasonUnspecified          = 0 // Unspecified reason for revocation
	RevocationReasonKeyCompromise        = 1 // The key associated with the certificate has been compromised
	RevocationReasonCACertCompromise     = 2 // The issuing CA certificate has been compromised
	RevocationReasonAffiliationChanged   = 3 // The entity's affiliation with the domain has changed
	RevocationReasonSuperseded           = 4 // The certificate has been superseded by another certificate
	RevocationReasonCessationOfOperation = 5 // The entity has ceased its operations (e.g., the domain is no longer used)
	RevocationReasonCertificateHold      = 6 // The certificate is placed on hold (temporary revocation)
)

type RevokeCertRequest struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason,omitempty"`
}

func (s *RestService) RevokeCertHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("RevokeCertHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	_, payload, err := s.parseKID(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	var revokeRequest RevokeCertRequest
	if err := json.Unmarshal(payload, &revokeRequest); err != nil {
		writeError(w, acme.MalformedError("Invalid request payload", nil))
		return
	}

	certDER, err := base64.RawURLEncoding.DecodeString(revokeRequest.Certificate)
	if err != nil {
		http.Error(w, "Invalid certificate encoding", http.StatusBadRequest)
		return
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		http.Error(w, "Invalid certificate format", http.StatusBadRequest)
		return
	}

	reason := revokeRequest.Reason
	if reason < 0 || reason > 10 {
		http.Error(w, "Invalid revocation reason", http.StatusBadRequest)
		return
	}

	certificateDAO, err := s.params.DAOFactory.ACMECertificateDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create certificate DAO"))
		return
	}
	entity, err := certificateDAO.Get(cert.SerialNumber.Uint64(), s.consistencyLevel)
	if err != nil {
		writeError(w, acme.MalformedError("Certificate not found", nil))
		return
	}

	entity.Status = acme.StatusRevoked

	if err := certificateDAO.Save(entity); err != nil {
		writeError(w, acme.ServerInternal("Failed to update certificate status"))
		return
	}

	s.logger.Debug("Revoking certificate", slog.String("serial", cert.SerialNumber.String()))

	// Revoke the certificate, without deleting keys. An ACME server should never
	// have a client key pair in any of the platform key stores.
	if err := s.ca.Revoke(cert, false); err != nil {
		writeError(w, acme.ServerInternal("Failed to revoke certificate"))
		return
	}

	w.WriteHeader(http.StatusOK)
}
