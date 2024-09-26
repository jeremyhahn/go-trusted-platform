package middleware

import (
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
)

type JsonWebTokenMiddleware interface {
	CreateSession(w http.ResponseWriter, r *http.Request) (service.Session, error)
	GenerateToken(w http.ResponseWriter, req *http.Request)
	AuthMiddleware
}

type AuthMiddleware interface {
	RefreshToken(w http.ResponseWriter, req *http.Request)
	Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc)
}
