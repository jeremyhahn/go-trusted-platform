package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

// DirectoryHandler responds to /acme/directory requests.
func (s *RestService) DirectoryHandler(w http.ResponseWriter, r *http.Request) {
	tos := fmt.Sprintf("%s%s", s.baseRESTURI, s.params.ACMEConfig.Server.TermsOfService)
	directory := acme.Directory{
		NewNonce:   fmt.Sprintf("%s/acme/new-nonce", s.baseRESTURI),
		NewAccount: fmt.Sprintf("%s/acme/new-account", s.baseRESTURI),
		NewOrder:   fmt.Sprintf("%s/acme/new-order", s.baseRESTURI),
		RevokeCert: fmt.Sprintf("%s/acme/revoke-cert", s.baseRESTURI),
		KeyChange:  fmt.Sprintf("%s/acme/key-change", s.baseRESTURI),
		Meta: acme.Meta{
			TermsOfService:     tos,
			Website:            s.baseRESTURI,
			CAAIdentities:      []string{s.params.CN},
			ExternalAccountReq: false,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(directory)
}
