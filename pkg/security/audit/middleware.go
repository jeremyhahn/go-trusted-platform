// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package audit

import (
	"context"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// HTTPMiddlewareConfig holds configuration for HTTP audit middleware
type HTTPMiddlewareConfig struct {
	// Logger is the audit logger
	Logger AuditLogger

	// ActorExtractor extracts the actor from the request
	ActorExtractor func(*http.Request) string

	// SkipPaths is a list of paths to skip auditing
	SkipPaths []string

	// IncludeHeaders includes specified headers in audit details
	IncludeHeaders []string

	// IncludeQueryParams includes query parameters in audit details
	IncludeQueryParams bool

	// ResourceExtractor extracts the resource from the request
	ResourceExtractor func(*http.Request) (resource, resourceType string)
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// HTTPAuditMiddleware returns an HTTP middleware that logs audit events
func HTTPAuditMiddleware(config HTTPMiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be skipped
			for _, path := range config.SkipPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Extract actor
			actor := "anonymous"
			if config.ActorExtractor != nil {
				actor = config.ActorExtractor(r)
			}

			// Extract resource
			var resource, resourceType string
			if config.ResourceExtractor != nil {
				resource, resourceType = config.ResourceExtractor(r)
			}

			// Extract source IP
			sourceIP := extractSourceIP(r)

			// Extract request ID from headers
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = r.Header.Get("X-Correlation-ID")
			}

			// Serve the request
			next.ServeHTTP(wrapped, r)

			// Build audit event
			builder := NewEventBuilder().
				WithActor(actor).
				WithAction(r.Method).
				WithMethod(r.Method).
				WithPath(r.URL.Path).
				WithSourceIP(sourceIP).
				WithStatusCode(wrapped.statusCode).
				WithDuration(time.Since(start))

			if resource != "" {
				builder.WithResource(resource, resourceType)
			}

			if requestID != "" {
				builder.WithRequestID(requestID)
			}

			// Set outcome based on status code
			outcome := OutcomeSuccess
			switch {
			case wrapped.statusCode >= 500:
				outcome = OutcomeError
			case wrapped.statusCode == 401 || wrapped.statusCode == 403:
				outcome = OutcomeDenied
			case wrapped.statusCode >= 400:
				outcome = OutcomeFailure
			}
			builder.WithOutcome(outcome)

			// Include headers if configured
			for _, header := range config.IncludeHeaders {
				if value := r.Header.Get(header); value != "" {
					builder.WithMetadata(header, value)
				}
			}

			// Include query params if configured
			if config.IncludeQueryParams && len(r.URL.Query()) > 0 {
				builder.WithDetail("query_params", r.URL.Query())
			}

			// Include user agent
			if ua := r.Header.Get("User-Agent"); ua != "" {
				builder.WithMetadata("user_agent", ua)
			}

			event := builder.Build()

			// Log async to not block response
			_ = config.Logger.LogAsync(event)
		})
	}
}

// extractSourceIP extracts the client IP from the request
func extractSourceIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// GRPCAuditInterceptor returns a gRPC unary server interceptor that logs audit events
func GRPCAuditInterceptor(config GRPCInterceptorConfig) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Check if method should be skipped
		for _, method := range config.SkipMethods {
			if strings.HasSuffix(info.FullMethod, method) {
				return handler(ctx, req)
			}
		}

		start := time.Now()

		// Extract actor
		actor := "anonymous"
		if config.ActorExtractor != nil {
			actor = config.ActorExtractor(ctx)
		}

		// Extract resource
		var resource, resourceType string
		if config.ResourceExtractor != nil {
			resource, resourceType = config.ResourceExtractor(ctx, info.FullMethod, req)
		}

		// Extract source IP from peer
		sourceIP := extractGRPCSourceIP(ctx)

		// Extract request ID from metadata
		requestID := extractGRPCMetadata(ctx, "x-request-id")
		if requestID == "" {
			requestID = extractGRPCMetadata(ctx, "x-correlation-id")
		}

		// Handle the request
		resp, err := handler(ctx, req)

		// Determine outcome
		outcome := OutcomeSuccess
		var statusCode int
		if err != nil {
			st, _ := status.FromError(err)
			statusCode = int(st.Code())
			switch st.Code() {
			case 7: // PermissionDenied
				outcome = OutcomeDenied
			case 16: // Unauthenticated
				outcome = OutcomeDenied
			case 13, 14, 15: // Internal, Unavailable, DataLoss
				outcome = OutcomeError
			default:
				outcome = OutcomeFailure
			}
		}

		// Build audit event
		builder := NewEventBuilder().
			WithActor(actor).
			WithAction(extractMethodName(info.FullMethod)).
			WithMethod(info.FullMethod).
			WithSourceIP(sourceIP).
			WithStatusCode(statusCode).
			WithDuration(time.Since(start)).
			WithOutcome(outcome)

		if resource != "" {
			builder.WithResource(resource, resourceType)
		}

		if requestID != "" {
			builder.WithRequestID(requestID)
		}

		event := builder.Build()

		// Log async to not block response
		_ = config.Logger.LogAsync(event)

		return resp, err
	}
}

// GRPCStreamAuditInterceptor returns a gRPC stream server interceptor that logs audit events
func GRPCStreamAuditInterceptor(config GRPCInterceptorConfig) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if method should be skipped
		for _, method := range config.SkipMethods {
			if strings.HasSuffix(info.FullMethod, method) {
				return handler(srv, ss)
			}
		}

		start := time.Now()
		ctx := ss.Context()

		// Extract actor
		actor := "anonymous"
		if config.ActorExtractor != nil {
			actor = config.ActorExtractor(ctx)
		}

		// Extract source IP from peer
		sourceIP := extractGRPCSourceIP(ctx)

		// Extract request ID from metadata
		requestID := extractGRPCMetadata(ctx, "x-request-id")
		if requestID == "" {
			requestID = extractGRPCMetadata(ctx, "x-correlation-id")
		}

		// Handle the stream
		err := handler(srv, ss)

		// Determine outcome
		outcome := OutcomeSuccess
		var statusCode int
		if err != nil {
			st, _ := status.FromError(err)
			statusCode = int(st.Code())
			switch st.Code() {
			case 7: // PermissionDenied
				outcome = OutcomeDenied
			case 16: // Unauthenticated
				outcome = OutcomeDenied
			case 13, 14, 15: // Internal, Unavailable, DataLoss
				outcome = OutcomeError
			default:
				outcome = OutcomeFailure
			}
		}

		// Build audit event
		builder := NewEventBuilder().
			WithActor(actor).
			WithAction(extractMethodName(info.FullMethod)).
			WithMethod(info.FullMethod).
			WithSourceIP(sourceIP).
			WithStatusCode(statusCode).
			WithDuration(time.Since(start)).
			WithOutcome(outcome).
			WithDetail("stream", true).
			WithDetail("client_stream", info.IsClientStream).
			WithDetail("server_stream", info.IsServerStream)

		if requestID != "" {
			builder.WithRequestID(requestID)
		}

		event := builder.Build()

		// Log async to not block response
		_ = config.Logger.LogAsync(event)

		return err
	}
}

// GRPCInterceptorConfig holds configuration for gRPC audit interceptors
type GRPCInterceptorConfig struct {
	// Logger is the audit logger
	Logger AuditLogger

	// ActorExtractor extracts the actor from the context
	ActorExtractor func(context.Context) string

	// SkipMethods is a list of method names to skip auditing
	SkipMethods []string

	// ResourceExtractor extracts the resource from the request
	ResourceExtractor func(ctx context.Context, method string, req any) (resource, resourceType string)
}

// extractGRPCSourceIP extracts the client IP from gRPC peer
func extractGRPCSourceIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	addr := p.Addr.String()
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// extractGRPCMetadata extracts a metadata value from gRPC context
func extractGRPCMetadata(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// extractMethodName extracts the method name from a full gRPC method path
func extractMethodName(fullMethod string) string {
	if idx := strings.LastIndex(fullMethod, "/"); idx != -1 {
		return fullMethod[idx+1:]
	}
	return fullMethod
}
