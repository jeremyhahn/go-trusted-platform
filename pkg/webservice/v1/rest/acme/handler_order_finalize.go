package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var orderFinalizeRequest struct {
	CSR string `json:"csr"`
}

func (s *RestService) OrderFinalizeHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("OrderFinalizeHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	account, payload, err := s.parseKID(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	fmt.Println(string(payload))

	orderDAO, err := s.daoFactory.ACMEOrderDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create order DAO"))
		return
	}

	vars := mux.Vars(r)
	strOrderID := vars["id"]
	orderID, err := strconv.ParseUint(strOrderID, 10, 64)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid order ID", nil))
		return
	}

	order, err := orderDAO.Get(orderID, s.consistencyLevel)
	if err != nil {
		writeError(w, acme.MalformedError("Order not found", nil))
		return
	}

	if order.AccountID != account.ID {
		writeError(w, acme.Unauthorized("Unauthorized"))
		return
	}

	if order.Status != acme.StatusReady {
		writeError(w, acme.OrderNotReady("Order is not ready for finalization"))
		return
	}

	if err := json.Unmarshal(payload, &orderFinalizeRequest); err != nil {
		writeError(w, acme.MalformedError("Invalid request payload", nil))
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(orderFinalizeRequest.CSR)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid CSR encoding", nil))
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid CSR", nil))
		return
	}

	csrPEM, err := certstore.EncodeCSR(csrDER)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode CSR to PEM"))
		return
	}

	matchesIdentifier := false
	for _, identifier := range order.Identifiers {
		if identifier.Value == csr.Subject.CommonName {
			matchesIdentifier = true
			break
		}
	}

	if !matchesIdentifier {
		writeError(w, acme.MalformedError("CSR does not match order identifiers", nil))
		return
	}

	order.Status = acme.StatusProcessing
	if err := orderDAO.Save(order); err != nil {
		writeError(w, acme.ServerInternal("Failed to update order status"))
		return
	}

	cert, err := s.ca.SignCSR(csrPEM, nil)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to sign CSR"))
		return
	}

	pem, err := certstore.EncodePEM(cert.Raw)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode certificate to PEM"))
		return
	}

	if err != nil {
		writeError(w, acme.ServerInternal("Failed to generate certificate ID"))
		return
	}

	certURL := fmt.Sprintf("%s/acme/cert/%d", s.baseRESTURI, cert.SerialNumber.Uint64())

	certificate := &entities.ACMECertificate{
		ID:        cert.SerialNumber.Uint64(),
		CertURL:   certURL,
		PEM:       string(pem),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}

	certDAO, err := s.daoFactory.ACMECertificateDAO()
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create certificate DAO"))
		return
	}
	if err := certDAO.Save(certificate); err != nil {
		writeError(w, acme.ServerInternal("Failed to save certificate"))
		return
	}

	order.Status = acme.StatusValid
	order.Certificate = certURL
	if err := orderDAO.Save(order); err != nil {
		writeError(w, acme.ServerInternal("Failed to update order"))
		return
	}

	s.orderResponse(w, order)
}
