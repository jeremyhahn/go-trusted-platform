package handlers

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
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"

	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

type OrderFinalizeRequest struct {
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

	orderDAO, err := s.params.DAOFactory.ACMEOrderDAO(account.ID)
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

	// Set the order status to processing
	order.Status = acme.StatusProcessing
	if err := orderDAO.Save(order); err != nil {
		writeError(w, acme.ServerInternal("Failed to update order status"))
		return
	}

	var finalizeRequest OrderFinalizeRequest

	// Decode the finalize request paylaod
	if err := json.Unmarshal(payload, &finalizeRequest); err != nil {
		writeError(w, acme.MalformedError("Invalid request payload", nil))
		return
	}

	// Decode the CSR from the request payload
	csrDER, err := base64.RawURLEncoding.DecodeString(finalizeRequest.CSR)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid CSR encoding", nil))
		return
	}

	var serialNumber uint64
	var pem []byte

	// Parse the CSR as a standard x509 certificate request
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {

		// Failed, attempt to parse as TCG-CSR-IDEVID for enroll-01
		if len(order.Identifiers) > 0 {
			if order.Identifiers[0].Type == acme.AuthzTypeIP.String() {

				serialNumber, pem, err = s.finalizeTCGCSR(
					order.Identifiers[0].Value, csrDER, w, r)
				if err != nil {
					writeError(w, acme.MalformedError("Invalid CSR", nil))
					return
				}

				// Send the final order response
				s.sendFinalizeResponse(orderDAO, order, serialNumber, pem, w)
				return
			}
		}
	}

	// ... continue processing x509 certificate request

	// Encode the CSR to PEM
	csrPEM, err := certstore.EncodeCSR(csrDER)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode CSR to PEM"))
		return
	}

	// Ensure the CSR matches the order identifiers
	matches, err := matchesIdentifier(csr, order)
	if err != nil {
		writeError(w, err.(*entities.Error))
		return
	}
	if !matches {
		writeError(w, acme.MalformedError("CSR does not match order identifiers", nil))
		return
	}

	// Sign the CSR
	cert, err := s.ca.SignCSR(csrPEM, nil)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to sign CSR"))
		return
	}

	serialNumber = cert.SerialNumber.Uint64()

	// Verify the certificate as a final sanity check
	if err := s.ca.Verify(cert); err != nil {
		writeError(w, acme.ServerInternal("Failed to verify certificate"))
		return
	}

	// Encode the certificate to PEM
	pem, err = certstore.EncodePEM(cert.Raw)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode certificate to PEM"))
		return
	}

	// Send the final order response
	s.sendFinalizeResponse(orderDAO, order, serialNumber, pem, w)
}

// Sends the final order repsonse to the client
func (s *RestService) sendFinalizeResponse(
	orderDAO dao.ACMEOrderDAO,
	order *entities.ACMEOrder,
	serialNumber uint64,
	pem []byte,
	w http.ResponseWriter) {

	certURL := fmt.Sprintf("%s/acme/cert/%d", s.baseRESTURI, serialNumber)

	certificate := &entities.ACMECertificate{
		ID:        serialNumber,
		CertURL:   certURL,
		PEM:       string(pem),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}

	certDAO, err := s.params.DAOFactory.ACMECertificateDAO()
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

// Check if the identifiers in the CSR match the order identifiers
func matchesIdentifier(
	csr *x509.CertificateRequest,
	order *entities.ACMEOrder) (bool, error) {

	// Ensure the identifier matches
	matchesIdentifier := false
	for _, identifier := range order.Identifiers {

		switch identifier.Type {

		case acme.AuthzTypePermanentIdentifier.String():
			permanentID, err := certstore.ParseCertificateRequestPermanentIdentifier(csr)
			if err != nil {
				return false, acme.MalformedError("Failed to parse permanent-identifier", nil)
			}
			if identifier.Value == permanentID {
				matchesIdentifier = true
				break
			}
		case acme.AuthzTypeDNS.String():
			if identifier.Value == csr.Subject.CommonName {
				matchesIdentifier = true
				break
			}

		default:
			return false,
				acme.UnsupportedIdentifier(fmt.Sprintf("Invalid identifier: %s", identifier.Type))
		}
	}

	return matchesIdentifier, nil
}

// Finalize a TCG-CSR-IDEVID for a successful enroll-01 challenge verification
func (s *RestService) finalizeTCGCSR(ip string, csrDER []byte, w http.ResponseWriter, r *http.Request) (uint64, []byte, error) {

	var pem []byte

	// Unmarshal the TCG-CSR-IDEVID
	tcgCSR, err := tpm2.UnmarshalIDevIDCSR(csrDER)
	if err != nil {
		return 0, nil, acme.MalformedError("Failed to parse TCG-CSR-IDEVID", nil)
	}

	// Use the CA identity to populate the certificate request subject
	caIdentity := s.ca.Identity()

	// Build the IDevID common name and internal CSR request object -

	// The TCG specifications regarding the TCG-CSR-IDEVID structure don't
	// provide the needed x509 PKIX subject for the client to send a proper
	// CSR. For now, this will only support "enterprise enrollments" where
	// it's assumed all devices are part of the same enterprise / domain as
	// this ACME server, but in the future, this will be extended to support
	// any domain via the TCG-CSR-IDEVID prodCAData field, where it will store
	// the necessary PKIX attributes. This, along with each platform having it's
	// own CA with cross-signing abilities, enables a decentralized, private
	// PKI Web of Trust between platforms.

	// Construct the common name for the certificate using the device
	// product model and serial number, prefixed with "idevid-" and
	// appending the internal domain name.
	idevidCN := fmt.Sprintf("%s-%s.%s",
		tcgCSR.CsrContents.ProdModel,
		tcgCSR.CsrContents.ProdSerial,
		s.params.DNSService.InternalDomain())

	// Build the IDevID certificate request
	tcgCSRRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:         idevidCN,
			Organization:       caIdentity.Subject.Organization,
			OrganizationalUnit: caIdentity.Subject.OrganizationalUnit,
			Country:            caIdentity.Subject.Country,
			Locality:           caIdentity.Subject.Locality,
			Province:           caIdentity.Subject.Province,
			Address:            caIdentity.Subject.Address,
			PostalCode:         caIdentity.Subject.PostalCode,
		},
	}

	// Sign the TCG-CSR-IDEVID
	iakDER, idevidDER, err := s.ca.SignTCGCSRIDevID(tcgCSR, tcgCSRRequest)
	idevidCert, err := x509.ParseCertificate(idevidDER)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to parse certificate"))
		return 0, nil, nil
	}

	// Build the IAK certificate request
	iakCertRequest := *tcgCSRRequest
	iakCertRequest.Subject.CommonName = fmt.Sprintf("iak-%s-%s",
		tcgCSR.CsrContents.ProdModel, tcgCSR.CsrContents.ProdSerial)

	// Encode the IAK certificate to PEM
	pem, err = certstore.EncodePEM(iakDER)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode IAK certificate to PEM"))
		return 0, nil, nil
	}

	// Encode the IDevID certificate to PEM
	idevidPEM, err := certstore.EncodePEM(idevidDER)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode IDevID certificate to PEM"))
		return 0, nil, nil
	}

	// Append the IDevID certificate to the IAK certificate
	pem = append(pem, idevidPEM...)

	// Register the FQDN with the DNS server if enabled in the platform configuration
	if s.params.DNSService != nil {
		if _, err := s.params.DNSService.Register(idevidCN, ip); err != nil {
			writeError(w, acme.ServerInternal("Failed to register FQDN with DNS server"))
			return 0, nil, nil
		}
	}

	// Save the device and it's attestation state to the datastore
	ekcert, err := x509.ParseCertificate(tcgCSR.CsrContents.EkCert)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to parse EK certificate"))
		return 0, nil, nil
	}
	ekcertPEM, err := certstore.EncodePEM(ekcert.Raw)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode EK certificate to PEM"))
		return 0, nil, nil
	}
	attestPEM, err := certstore.EncodePEM(tcgCSR.CsrContents.AttestPub)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode attestation certificate to PEM"))
		return 0, nil, nil
	}
	signingPEM, err := certstore.EncodePEM(tcgCSR.CsrContents.SigningPub)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to encode signing certificate to PEM"))
		return 0, nil, nil
	}
	err = s.params.DeviceService.Save(&deviceentities.Device{
		ID:        ekcert.SerialNumber.Uint64(),
		AttestPub: string(attestPEM),
		EKCert:    string(ekcertPEM),
		EventLog:  tcgCSR.CsrContents.BootEvntLog,
		// HashAlgoId: tcgCSR.CsrContents.HashAlgoId,
		Model:      string(tcgCSR.CsrContents.ProdModel),
		Serial:     string(tcgCSR.CsrContents.ProdSerial),
		SigningPub: string(signingPEM),
	})
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to save device"))
		return 0, nil, nil
	}

	// TODO: implement device profile features to support automated remote provisioning
	// of the device, enforce system state policies, compare initial device state with an
	// expected pre-provisioning state, capture a new device boot log after provisioning,
	// etc.

	return idevidCert.SerialNumber.Uint64(), pem, nil
}
