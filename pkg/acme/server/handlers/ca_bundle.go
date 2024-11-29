package handlers

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

func (s *RestService) CABundleHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("CABundleHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	var err error

	vars := mux.Vars(r)
	varStoreType := vars["storeType"]
	varKeyAlgo := vars["keyAlgo"]

	var bundle []byte
	if varStoreType == "" && varKeyAlgo == "" {

		// Serve the CA bundle that was used to sign the web server TLS certificate
		bundle, err = s.ca.CABundle(&s.tlsStoreType, &s.tlsKeyAlgorithm)
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to get CA bundle"))
			return
		}

	} else {

		// Serve the CA bundle that was requested by the client
		storeType, err := keystore.ParseStoreType(strings.ToLower(varStoreType))
		if err != nil {
			writeError(w, acme.MalformedError("Invalid store type", nil))
			return
		}

		keyAlgo, err := keystore.ParseKeyAlgorithm(varKeyAlgo)
		if err != nil {
			writeError(w, acme.MalformedError("Invalid key algorithm", nil))
			return
		}

		bundle, err = s.ca.CABundle(&storeType, &keyAlgo)
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to get CA bundle"))
			return
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(bundle)
}
