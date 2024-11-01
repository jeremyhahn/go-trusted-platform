package acme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

func (s *RestService) OrdersListHandler(w http.ResponseWriter, r *http.Request) {

	s.logger.Debug("OrdersListHandler", "method", r.Method, "url", r.URL)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.Debugf("%s: %s\n", name, value)
		}
	}

	var page int64
	var err error

	vars := mux.Vars(r)
	strPage := vars["page"]

	if len(strPage) > 0 {
		page, err = strconv.ParseInt(strPage, 10, 64)
		if err != nil {
			writeError(w, acme.MalformedError("Invalid page ID", nil))
			return
		}
	}

	account, payload, err := s.parseKID(r)
	if err != nil {
		writeError(w, acme.MalformedError("Failed to parse account key", nil))
		return
	}

	fmt.Println(account)
	fmt.Println(string(payload))

	orderDAO, err := s.daoFactory.ACMEOrderDAO(account.ID)
	if err != nil {
		writeError(w, acme.ServerInternal("Failed to create order DAO"))
		return
	}

	// // Retrieve the persisted account
	// accountDAO, err := s.daoFactory.ACMEAccountDAO()
	// if err != nil {
	// 	writeError(w, ServerInternal("Failed to create account DAO"))
	// 	return
	// }
	// account, err := accountDAO.Get(accountID, s.consistencyLevel)
	// if err != nil {
	// 	writeError(w, AccountDoesNotExist("Account does not exist"))
	// 	return
	// }

	if r.Method == http.MethodGet || r.Method == http.MethodPost {

		// // Fetch orders for the account
		// orderDAO, err := s.daoFactory.ACMEOrderDAO()
		// if err != nil {
		// 	writeError(w, ServerInternal("Failed to create order DAO"))
		// 	return
		// }

		nextPage, err := parseNextLinkHeaderFromRequest(r)
		if err != nil {
			writeError(w, acme.MalformedError("Invalid Link header", nil))
			return
		}
		pageQuery := datastore.NewPageQuery()
		pageQuery.Page = nextPage

		pageResult, err := orderDAO.Page(pageQuery, s.consistencyLevel)
		if err != nil {
			writeError(w, acme.ServerInternal("Failed to retrieve orders"))
			return
		}

		orderURLs := []string{}
		for _, order := range pageResult.Entities {
			orderURLs = append(orderURLs, order.URL)
		}
		response := map[string][]string{
			"orders": orderURLs,
		}

		w.Header().Set("Content-Type", "application/json")
		if pageResult.HasMore {
			w.Header().Set("Link",
				fmt.Sprintf("%s/acme/account/%d/orders?page=%d", s.baseRESTURI, account.ID, page))
		}
		json.NewEncoder(w).Encode(response)

	} else {
		writeError(w, acme.MalformedError("Method not allowed", nil))
	}
}
