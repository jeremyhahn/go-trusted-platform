package daemon

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// restMethodActions maps an HTTP method to the action it performs on a
// daemon REST resource, matching the gRPC method permissions. A method that
// is not listed is refused, never defaulted.
var restMethodActions = map[string]string{
	http.MethodGet:    "read",
	http.MethodPost:   "write",
	http.MethodPut:    "write",
	http.MethodPatch:  "write",
	http.MethodDelete: "delete",
}

// restScopeAction returns the action a request on resource performs: read,
// write or delete. A POST whose route template ends in one of readOnlyPosts
// only evaluates its body, so it is a read, as its gRPC method is.
func restScopeAction(resource string, readOnlyPosts []string, method, route string) (string, error) {
	action, ok := restMethodActions[method]
	if !ok {
		return "", restapi.ErrRouteForbidden{Scope: resource + ":*", Reason: "method " + method + " is not served"}
	}
	if method == http.MethodPost {
		for _, suffix := range readOnlyPosts {
			if strings.HasSuffix(route, suffix) {
				return "read", nil
			}
		}
	}
	return action, nil
}

// restRouteTemplate is the path template of the matched route, or the
// request path when no route matched.
func restRouteTemplate(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if template, err := route.GetPathTemplate(); err == nil {
			return template
		}
	}
	return r.URL.Path
}
