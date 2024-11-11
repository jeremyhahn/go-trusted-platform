package handlers

import (
	"fmt"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

func (s *RestService) NewNonceHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("NewNonceHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	nonce, err := acme.GenerateNonce(nonceSize)
	if err != nil {
		writeError(w, acme.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Link", fmt.Sprintf("%s/acme/directory>;rel=\"index\"", s.baseRESTURI))

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
	} else if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
