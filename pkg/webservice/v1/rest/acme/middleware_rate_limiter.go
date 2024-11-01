package acme

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// RateLimiter holds the configuration for a rate-limiting policy
type RateLimiter struct {
	MaxRequests int                  // Maximum number of requests allowed
	Interval    time.Duration        // Time interval for rate limit
	Tokens      map[string]int       // Tokens per resource (e.g., per IP or KID)
	LastRequest map[string]time.Time // Track last request time per resource
	mu          sync.Mutex           // Mutex to synchronize access
}

// NewRateLimiter creates a new rate limiter with the specified maximum requests and interval
func NewRateLimiter(maxRequests int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		MaxRequests: maxRequests,
		Interval:    interval,
		Tokens:      make(map[string]int),
		LastRequest: make(map[string]time.Time),
	}
}

// MiddlewareFunc generates a rate-limiting middleware function using a client IP or JWS KID
func (rl *RateLimiter) MiddlewareFunc(resourceKeyFunc func(r *http.Request) string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rl.mu.Lock()
			defer rl.mu.Unlock()

			resourceKey := resourceKeyFunc(r) // Generate the resource key (IP or KID)

			// Calculate time since the last request for this resource
			now := time.Now()
			elapsed := now.Sub(rl.LastRequest[resourceKey])

			// Add tokens back based on time passed
			tokensToAdd := int(elapsed.Seconds() / rl.Interval.Seconds())
			rl.Tokens[resourceKey] = min(rl.MaxRequests, rl.Tokens[resourceKey]+tokensToAdd)

			// Update last request time
			rl.LastRequest[resourceKey] = now

			// Check if we have tokens left
			if rl.Tokens[resourceKey] > 0 {
				rl.Tokens[resourceKey]--
				next.ServeHTTP(w, r) // Serve the request
			} else {
				// Rate limit exceeded, return 429
				w.Header().Set("Retry-After", rl.Interval.String())
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			}
		})
	}
}

// Utility function to determine the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Generates a rate-limiting client ID by parsing the JWS KID or
// falling back to the client's IP address
func ClientID(r *http.Request) string {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return r.RemoteAddr
	}
	defer r.Body.Close()

	// Restore the body so it can be read again by the handler
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	jwsString := strings.TrimSpace(string(body))
	jws, err := jose.ParseSigned(jwsString, allowedAlgs)
	if err != nil {
		return r.RemoteAddr
	}

	if len(jws.Signatures) == 0 {
		return r.RemoteAddr
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.KeyID == "" {
		return r.RemoteAddr
	}
	return protectedHeader.KeyID
}
