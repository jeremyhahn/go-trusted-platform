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

// Package iam provides REST API handlers for Identity and Access Management operations.
//
// This package implements the REST interface for the IAM subsystem, exposing endpoints
// for managing users, roles, tenants, policies, and applications through
// a standard HTTP/HTTPS interface. It serves as a protocol adapter that translates
// REST requests to gRPC calls against the underlying QuicBaaS IAM service.
//
// # Architecture
//
// The package follows a clean separation of concerns:
//
//   - handlers.go: HTTP request handlers for all IAM operations
//   - router.go: Route registration with gorilla/mux
//   - types.go: Request and response DTOs
//   - errors.go: Typed errors for REST-specific error conditions
//
// # Supported Operations
//
// User Management:
//
//   - POST   /api/v1/iam/tenants/{tenant}/users           - Create user
//   - GET    /api/v1/iam/tenants/{tenant}/users/{id}      - Get user
//   - GET    /api/v1/iam/tenants/{tenant}/users           - List users
//   - PUT    /api/v1/iam/tenants/{tenant}/users/{id}      - Update user
//   - DELETE /api/v1/iam/tenants/{tenant}/users/{id}      - Delete user
//   - POST   /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role} - Assign role
//   - DELETE /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role} - Revoke role
//
// Role Management:
//
//   - POST   /api/v1/iam/tenants/{tenant}/roles           - Create role
//   - GET    /api/v1/iam/tenants/{tenant}/roles/{id}      - Get role
//   - GET    /api/v1/iam/tenants/{tenant}/roles           - List roles
//   - PUT    /api/v1/iam/tenants/{tenant}/roles/{id}      - Update role
//   - DELETE /api/v1/iam/tenants/{tenant}/roles/{id}      - Delete role
//
// Tenant Management:
//
//   - POST   /api/v1/iam/tenants                          - Create tenant
//   - GET    /api/v1/iam/tenants/{id}                     - Get tenant
//   - GET    /api/v1/iam/tenants                          - List tenants
//   - PUT    /api/v1/iam/tenants/{id}                     - Update tenant
//   - DELETE /api/v1/iam/tenants/{id}                     - Delete tenant
//
// Policy Management:
//
//   - POST   /api/v1/iam/tenants/{tenant}/policies        - Create policy
//   - GET    /api/v1/iam/tenants/{tenant}/policies/{id}   - Get policy
//   - GET    /api/v1/iam/tenants/{tenant}/policies        - List policies
//   - PUT    /api/v1/iam/tenants/{tenant}/policies/{id}   - Update policy
//   - DELETE /api/v1/iam/tenants/{tenant}/policies/{id}   - Delete policy
//   - POST   /api/v1/iam/tenants/{tenant}/policies/validate - Validate policy
//   - POST   /api/v1/iam/tenants/{tenant}/policies/test   - Test policy
//
// Permission Checks:
//
//   - POST   /api/v1/iam/tenants/{tenant}/permissions/check - Live PEP decision
//
// Application Management:
//
//   - POST   /api/v1/iam/tenants/{tenant}/apps            - Register app
//   - GET    /api/v1/iam/tenants/{tenant}/apps/{id}       - Get app
//   - GET    /api/v1/iam/tenants/{tenant}/apps            - List apps
//   - PUT    /api/v1/iam/tenants/{tenant}/apps/{id}       - Update app
//   - DELETE /api/v1/iam/tenants/{tenant}/apps/{id}       - Delete app
//   - POST   /api/v1/iam/tenants/{tenant}/apps/{id}/rotate-secret - Rotate secret
//
// Authorization:
//
//   - POST   /api/v1/iam/tenants/{tenant}/authorize       - Check permission
//
// # Error Handling
//
// The package uses typed errors that map to appropriate HTTP status codes:
//
//   - 400 Bad Request: Invalid input, missing required fields
//   - 401 Unauthorized: Authentication or authorization failures
//   - 404 Not Found: Resource not found
//   - 500 Internal Server Error: Unexpected server errors
//
// All errors include structured JSON responses with error details.
//
// # Pagination
//
// List endpoints support pagination via query parameters:
//
//   - limit: Maximum number of items to return (default: 50, max: 1000)
//   - offset: Number of items to skip (default: 0)
//
// Example:
//
//	GET /api/v1/iam/tenants/my-tenant/users?limit=20&offset=40
//
// # Usage
//
// The handlers are typically initialized and registered in the webservice setup:
//
//	handlers := iam.NewIAMHandlers(logger, iamClient, pepClient, respWriter)
//	router := iam.NewRouter(handlers)
//	router.RegisterRoutes(muxRouter)
//
// # Thread Safety
//
// All handlers are safe for concurrent use. The underlying gRPC clients handle
// connection pooling and request isolation.
package iam
