package router

import "github.com/gorilla/mux"

type WebServiceRouter interface {
	RegisterRoutes(router *mux.Router, baseURI string) []string
}
