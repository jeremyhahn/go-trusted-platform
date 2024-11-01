package acme

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

func (s *RestService) CertificateHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("CertificateHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	strCertID := mux.Vars(r)["id"]
	certID, err := strconv.ParseUint(strCertID, 10, 64)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid certificate ID", nil))
		return
	}
	certificateDAO, err := s.daoFactory.ACMECertificateDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create certificate DAO"))
		return
	}
	certificate, err := certificateDAO.Get(certID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.MalformedError("Certificate not found", nil))
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(certificate.PEM))
}
