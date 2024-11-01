package acme

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
)

func (s *RestService) OrderHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("OrderHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	account, _, err := s.parseKID(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	strOrderID := mux.Vars(r)["id"]
	orderID, err := strconv.ParseUint(strOrderID, 10, 64)
	if err != nil {
		writeError(w, acme.MalformedError("Invalid order ID", nil))
		return
	}

	orderDAO, err := s.daoFactory.ACMEOrderDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create order DAO"))
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

	s.orderResponse(w, order)
}
