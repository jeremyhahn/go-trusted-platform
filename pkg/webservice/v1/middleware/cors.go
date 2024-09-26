package middleware

import (
	"net/http"
)

// CORSOptions defines the settings for CORS configuration
type CORSOptions struct {
	AllowedOrigins   []string // List of allowed origins
	AllowedMethods   []string // List of allowed methods (e.g., GET, POST)
	AllowedHeaders   []string // List of allowed headers
	AllowCredentials bool     // Whether to allow credentials (cookies, authorization headers)
}

// CORSMiddleware creates a new CORS middleware with the given options
func CORSMiddleware(options CORSOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if isAllowedOrigin(origin, options.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", join(options.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", join(options.AllowedHeaders, ", "))

				if options.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isAllowedOrigin checks if the given origin is in the list of allowed origins
func isAllowedOrigin(origin string, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return false
	}

	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
	}

	return false
}

// join concatenates a slice of strings into a single string separated by a given separator
func join(strings []string, separator string) string {
	result := ""
	for i, str := range strings {
		result += str
		if i < len(strings)-1 {
			result += separator
		}
	}
	return result
}
