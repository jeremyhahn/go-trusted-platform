# ROADMAP: Phase 1 - User Registration & Tenant Management

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Started 2026-01-18 · Completed 2026-01-21 · Archived 2026-08-18.
> 131 of 133 checklist items are complete; the two open items (`web/README.md`
> at line 312 and `web/docs/testing.md` at line 316) are documentation tasks
> superseded by the feature-folder migration, not outstanding engineering work.
>
> The shipped behaviour this roadmap planned is now documented as requirements
> in [`docs/tenant/`](tenant/) (platform tenancy) and [`docs/iam/`](iam/)
> (users, groups, roles, invitations). Build against those, not against this
> file.

---

## Overview

Integrate tenant management with the existing WebAuthn registration flow:
1. Add TenantID to User entity (new users get new tenant, invited users join existing)
2. Create invitation flow for tenant owners to invite team members
3. Integrate with QuicBaaS OIDC for token issuance with tenant claims
4. Comprehensive testing (unit, integration, E2E UI)
5. Update all relevant documentation

## Current State

| Component | Location | Status |
|-----------|----------|--------|
| WebAuthn handlers | `pkg/webservice/v1/webauthn/webauthn.go` | COMPLETE - Tenant integrated |
| User entity | `pkg/store/datastore/entities/user.go` | COMPLETE - TenantID, IsTenantOwner |
| Invitation entity | `pkg/store/datastore/entities/invitation.go` | COMPLETE |
| TenantManager | `pkg/tenant/manager.go` | COMPLETE (VLAN, quota, DEK) |
| QuicBaaS IAM | `pkg/api/mcp/quicbaas_auth.go` | TokenValidator exists |
| Frontend | `web/` | Next.js 16, WebAuthn works, no tests |
| Docs - IAM | `docs/iam/` | COMPLETE - user-registration.md |
| Docs - Auth | `docs/auth/` | COMPLETE - invitation-flow.md |
| Docs - Tenant | `docs/tenant/` | COMPLETE - user-relationship.md |

---

## Implementation

### Phase 0: Project Consolidation (Monorepo) - COMPLETE

Frontend project has been moved into go-trusted-platform for unified development.

**1. Move Frontend to web/** - COMPLETE
- [x] Source: `/home/jhahn/sources/go-trusted-platform-web` (archived)
- [x] Destination: `go-trusted-platform/web/`
- [x] Preserve: All source files, configs, package.json, .gitignore

**2. Update Makefile** - COMPLETE
- [x] Add `web-install`: Install npm dependencies
- [x] Add `web-build`: Build frontend
- [x] Add `web-dev`: Run dev server
- [x] Add `web-test`: Run Playwright E2E tests
- [x] Add `web-lint`: Run ESLint/TypeScript checks
- [x] Update `build-public-html` to use local `web/` directory
- [x] Update `build-public-html-host` to use local `web/` directory
- [x] Remove external repository clone logic

**3. Update Documentation** - COMPLETE
- [x] Update `docs/` references to point to `web/`

**Resulting Structure:**
```
go-trusted-platform/
├── web/                    # Frontend (Next.js 16)
│   ├── src/
│   ├── e2e/               # Playwright tests (Phase 1F)
│   ├── package.json
│   └── tsconfig.json
├── pkg/                    # Backend (Go)
├── docs/                   # Unified documentation
├── test/integration/       # Backend integration tests
└── Makefile               # Drives both Go and Node.js builds
```

---

### Phase 1A: Entity Layer - COMPLETE

**1. Update User Entity** - COMPLETE
- [x] File: `pkg/store/datastore/entities/user.go`
- [x] Add: `TenantID string`, `IsTenantOwner bool`, `CreatedAt`, `UpdatedAt`

**2. Create Invitation Entity** - COMPLETE
- [x] File: `pkg/store/datastore/entities/invitation.go` (NEW)
- [x] Fields: ID, Token, TenantID, Email, Role, Status, InvitedByID, ExpiresAt
- [x] Status enum: pending, accepted, expired, revoked

**3. Update Registration Entity** - COMPLETE
- [x] File: `pkg/store/datastore/entities/registration.go`
- [x] Add: `InvitationToken string` (optional, for invited users)

### Phase 1B: DAO Layer - COMPLETE

**4. Add InvitationDAO Interface** - COMPLETE
- [x] File: `pkg/store/datastore/types.go`
- [x] Methods: GetByToken, GetByEmail, GetByTenant, GetPendingByTenant

**5. Implement InvitationDAO** - COMPLETE
- [x] File: `pkg/store/datastore/kvstore/invitation.go` (NEW)
- [x] Follow existing DAO patterns (registration.go, user.go)

**6. Update Factory** - COMPLETE
- [x] File: `pkg/store/datastore/kvstore/factory.go`
- [x] Add: `InvitationDAO()` method

### Phase 1C: Service Layer - COMPLETE

**7. Create InvitationService** - COMPLETE
- [x] File: `pkg/platform/service/invitation.go` (NEW)
- [x] Methods: Create, GetByToken, Accept, Revoke, ListByTenant, CleanupExpired
- [x] Only tenant owners can create invitations

**8. Extend UserService** - COMPLETE
- [x] File: `pkg/platform/service/user.go`
- [x] Add: GetByEmail, GetByTenant, IsTenantOwner

**9. Create TenantUserService (Orchestration)** - COMPLETE
- [x] File: `pkg/platform/service/tenant_user.go` (NEW)
- [x] Key methods:
  - `RegisterNewUser`: Create tenant via TenantManager, set user as owner
  - `RegisterInvitedUser`: Validate invitation, join existing tenant
  - `IssueToken`: Use QuicBaaS IAM for JWT with tenant_id claim

### Phase 1D: API Layer - COMPLETE

**10. Update WebAuthn Handler** - COMPLETE
- [x] File: `pkg/webservice/v1/webauthn/webauthn.go`
- [x] BeginRegistration: Accept optional `invitation_token`
- [x] FinishRegistration: Call TenantUserService, issue OIDC token

**11. Create Invitation Handler** - COMPLETE
- [x] File: `pkg/webservice/v1/invitation/handler.go` (NEW)
- [x] Routes:
  - `POST /api/v1/invitations` - Create (owner only)
  - `GET /api/v1/invitations` - List tenant invitations
  - `GET /api/v1/invitations/token/:token` - Get by token (public)
  - `DELETE /api/v1/invitations/:id` - Revoke

**12. Create TenantContext Middleware** - COMPLETE
- [x] File: `pkg/webservice/v1/middleware/tenant_context.go` (NEW)
- [x] Extract tenant_id from JWT, add to request context

**13. Register Routes** - COMPLETE
- [x] File: `pkg/webservice/v1/router/invitation.go` (NEW)

**14. gRPC Proto File** - COMPLETE (needs buf generate)
- [x] File: `pkg/api/grpc/proto/invitation.proto` (NEW)

### Phase 1E: Frontend Implementation - COMPLETE

**14. Create AuthContext Provider** - COMPLETE
- [x] File: `web/src/contexts/AuthContext.tsx` (NEW)
- [x] Decode JWT, expose tenantId, userId, roles

**15. Update WebAuthn Page** - COMPLETE
- [x] File: `web/src/app/auth/webauthn/page.tsx`
- [x] Accept `?invitation=TOKEN` query param
- [x] Pass token to registration endpoint
- [x] Show different UI for invited vs new users

**16. Create Invitation Admin Page** - COMPLETE
- [x] File: `web/src/app/admin/invitations/page.tsx` (NEW)
- [x] Form to invite by email + role
- [x] List pending/accepted invitations
- [x] Revoke button for pending

**17. Create Tenant Dashboard** - COMPLETE
- [x] File: `web/src/app/admin/tenant/page.tsx` (NEW)
- [x] Show tenant info (ID, name, member count)
- [x] Navigation to invitations, members

---

### Phase 1F: UI Integration Testing (Playwright) - COMPLETE

**18. Setup Playwright Testing Framework** - COMPLETE
- [x] File: `web/package.json` - Add Playwright deps
- [x] File: `web/playwright.config.ts` (NEW)
- [x] File: `web/e2e/` directory (NEW)

```json
// package.json additions
"devDependencies": {
  "@playwright/test": "^1.40.0"
},
"scripts": {
  "test:e2e": "playwright test",
  "test:e2e:ui": "playwright test --ui",
  "test:e2e:headed": "playwright test --headed"
}
```

**19. WebAuthn Registration E2E Tests** - COMPLETE
- [x] File: `web/e2e/auth.spec.ts` (NEW)
- [x] Tests:
  - New user registration creates tenant
  - Registration form validation
  - Successful registration redirects to protected page
  - JWT cookie contains tenant_id
  - Logout clears session

**20. Invitation Flow E2E Tests** - COMPLETE
- [x] File: `web/e2e/invitations.spec.ts` (NEW)
- [x] Tests:
  - Tenant owner can access invitation page
  - Create invitation form works
  - Invitation link shows in UI
  - Invited user sees correct UI state
  - Invited user joins correct tenant
  - Non-owner cannot access invitation page
  - Expired invitation shows error

**21. Tenant Isolation E2E Tests** - COMPLETE
- [x] File: `web/e2e/tenant-isolation.spec.ts` (NEW)
- [x] Tests:
  - User A cannot see User B's data
  - Tenant context persists across navigation
  - Logout clears tenant context

**22. WebAuthn Mock for CI** - COMPLETE
- [x] File: `web/e2e/fixtures/webauthn-mock.ts` (NEW)
- [x] Mock WebAuthn API for headless CI testing
- [x] Use virtual authenticator in Playwright

---

### Phase 1G: Backend Unit Tests - COMPLETE

**23. Entity Tests** - COMPLETE
- [x] File: `pkg/store/datastore/entities/invitation_test.go` (NEW)
- [x] File: `pkg/store/datastore/entities/user_test.go` (EXTEND)

**24. DAO Tests** - COMPLETE
- [x] File: `pkg/store/datastore/kvstore/invitation_test.go` (NEW)

**25. Service Tests** - COMPLETE
- [x] File: `pkg/platform/service/invitation_test.go` (NEW)
- [x] File: `pkg/platform/service/tenant_user_test.go` (NEW)

**26. Handler Tests** - COMPLETE
- [x] File: `pkg/webservice/v1/invitation/handler_test.go` (NEW)
- [x] File: `pkg/webservice/v1/webauthn/webauthn_test.go` (EXTEND)

### Phase 1H: Backend Integration Tests - COMPLETE

**27. User Registration Integration** - COMPLETE
- [x] File: `test/integration/user_registration/registration_test.go` (NEW)
- [x] Tests:
  - New user registration E2E (creates tenant)
  - Invited user registration E2E (joins tenant)
  - Multi-protocol (REST, gRPC)

**28. Invitation API Integration** - COMPLETE
- [x] File: `test/integration/invitation/invitation_test.go` (NEW)
- [x] Tests:
  - Create invitation (owner only)
  - List invitations
  - Accept invitation
  - Revoke invitation
  - Expired invitation handling
  - Multi-protocol (REST, gRPC)

**29. Tenant Isolation Integration** - COMPLETE
- [x] File: `test/integration/tenant/isolation_test.go` (NEW)
- [x] Tests:
  - User A cannot access User B's tenant resources
  - Token contains correct tenant_id
  - Authorization enforced at service layer

---

### Phase 1I: Documentation - COMPLETE

**30. Update IAM Documentation** - COMPLETE
- [x] File: `docs/iam/user-registration.md` (NEW)
  - WebAuthn registration flow
  - Tenant auto-creation
  - JWT token structure with tenant_id

- [x] File: `docs/iam/authentication.md` (UPDATE)
  - Add WebAuthn + tenant section
  - Token claims documentation

**31. Update Auth Documentation** - COMPLETE
- [x] File: `docs/auth/invitation-flow.md` (NEW)
  - Complete invitation lifecycle
  - Token generation and validation
  - Email + role assignment
  - Flow diagrams

- [x] File: `docs/auth/README.md` (UPDATE)
  - Link to new invitation docs

**32. Update Tenant Documentation** - COMPLETE
- [x] File: `docs/tenant/user-relationship.md` (NEW)
  - User-tenant association model
  - Owner vs member roles
  - Tenant creation triggers

- [x] File: `docs/tenant/architecture.md` (UPDATE)
  - Add user relationship diagram
  - Update entity diagrams

- [x] File: `docs/tenant/api-reference.md` (UPDATE)
  - Add invitation API endpoints

**33. API Reference Updates** - COMPLETE
- [x] File: `docs/iam/api-reference-invitations.md` (NEW)
  - Add invitation endpoints
  - Add user-tenant endpoints

**34. Frontend Documentation** - PENDING
- [ ] File: `web/README.md` (UPDATE)
  - Add E2E testing instructions
  - Add auth flow documentation

- [ ] File: `web/docs/testing.md` (NEW)
  - Playwright setup
  - Running tests locally
  - CI integration
  - WebAuthn mocking

---

### Phase 1J: SDKs - COMPLETE

**35. Go SDK** - COMPLETE
- [x] File: `sdk/go/services/invitation/` - Invitation service client
- [x] File: `sdk/go/services/tenant/` - Tenant service client

**36. JavaScript SDK** - COMPLETE
- [x] File: `sdk/javascript/src/services/invitation-service.ts` - Invitation service
- [x] React hooks for invitation management

---

## File Summary

### Backend Files

| File | Action | Status |
|------|--------|--------|
| `pkg/store/datastore/entities/user.go` | MODIFY | COMPLETE |
| `pkg/store/datastore/entities/invitation.go` | CREATE | COMPLETE |
| `pkg/store/datastore/entities/registration.go` | MODIFY | COMPLETE |
| `pkg/store/datastore/types.go` | MODIFY | COMPLETE |
| `pkg/store/datastore/kvstore/invitation.go` | CREATE | COMPLETE |
| `pkg/store/datastore/kvstore/factory.go` | MODIFY | COMPLETE |
| `pkg/platform/service/invitation.go` | CREATE | COMPLETE |
| `pkg/platform/service/tenant_user.go` | CREATE | COMPLETE |
| `pkg/platform/service/user.go` | MODIFY | COMPLETE |
| `pkg/webservice/v1/webauthn/webauthn.go` | MODIFY | COMPLETE |
| `pkg/webservice/v1/invitation/handler.go` | CREATE | COMPLETE |
| `pkg/webservice/v1/router/invitation.go` | CREATE | COMPLETE |
| `pkg/webservice/v1/middleware/tenant_context.go` | CREATE | COMPLETE |
| `pkg/api/grpc/proto/invitation.proto` | CREATE | COMPLETE |

### Frontend Files

| File | Action | Status |
|------|--------|--------|
| `package.json` | MODIFY | COMPLETE |
| `playwright.config.ts` | CREATE | COMPLETE |
| `src/contexts/AuthContext.tsx` | CREATE | COMPLETE |
| `src/app/auth/webauthn/page.tsx` | MODIFY | COMPLETE |
| `src/app/admin/invitations/page.tsx` | CREATE | COMPLETE |
| `src/app/admin/tenant/page.tsx` | CREATE | COMPLETE |
| `e2e/auth.spec.ts` | CREATE | COMPLETE |
| `e2e/invitations.spec.ts` | CREATE | COMPLETE |
| `e2e/tenant.spec.ts` | CREATE | COMPLETE |
| `e2e/tenant-isolation.spec.ts` | CREATE | COMPLETE |
| `e2e/webauthn-flow.spec.ts` | CREATE | COMPLETE |
| `e2e/fixtures/webauthn-mock.ts` | CREATE | COMPLETE |
| `e2e/fixtures/auth-setup.ts` | CREATE | COMPLETE |
| `e2e/fixtures/api-mock.ts` | CREATE | COMPLETE |

### Test Files

| File | Action | Status |
|------|--------|--------|
| `pkg/store/datastore/entities/invitation_test.go` | CREATE | COMPLETE |
| `pkg/store/datastore/kvstore/invitation_test.go` | CREATE | COMPLETE |
| `pkg/platform/service/invitation_test.go` | CREATE | COMPLETE |
| `pkg/platform/service/tenant_user_test.go` | CREATE | COMPLETE |
| `pkg/webservice/v1/invitation/handler_test.go` | CREATE | COMPLETE |
| `test/integration/user_registration/registration_test.go` | CREATE | COMPLETE |
| `test/integration/invitation/invitation_test.go` | CREATE | COMPLETE |
| `test/integration/tenant/isolation_test.go` | CREATE | COMPLETE |

### Documentation Files

| File | Action | Status |
|------|--------|--------|
| `docs/iam/user-registration.md` | CREATE | COMPLETE |
| `docs/iam/authentication.md` | UPDATE | COMPLETE |
| `docs/iam/api-reference-invitations.md` | CREATE | COMPLETE |
| `docs/auth/invitation-flow.md` | CREATE | COMPLETE |
| `docs/auth/README.md` | UPDATE | COMPLETE |
| `docs/tenant/user-relationship.md` | CREATE | COMPLETE |
| `docs/tenant/architecture.md` | UPDATE | COMPLETE |
| `docs/tenant/api-reference.md` | UPDATE | COMPLETE |
| `web/README.md` | UPDATE | COMPLETE |
| `web/docs/testing.md` | CREATE | COMPLETE |

### SDK Files

| File | Action | Status |
|------|--------|--------|
| `sdk/go/services/invitation/` | CREATE | COMPLETE |
| `sdk/go/services/tenant/` | CREATE | COMPLETE |
| `sdk/javascript/src/services/invitation-service.ts` | CREATE | COMPLETE |

---

## Registration Flows

### New User Flow
```
1. User visits /auth/webauthn (no invitation param)
2. POST /api/v1/webauthn/registration/begin {username}
3. WebAuthn ceremony (passkey enrollment)
4. POST /api/v1/webauthn/registration/finish
5. TenantUserService.RegisterNewUser():
   - Generate tenant UUID
   - TenantManager.CreateTenant()
   - Set user.TenantID, user.IsTenantOwner = true
   - Save user
6. Issue JWT with tenant_id claim via QuicBaaS IAM
7. Redirect to /protected
```

### Invited User Flow
```
1. Tenant owner: POST /api/v1/invitations {email, role}
2. Invitation created with one-time token
3. Owner sends link: /auth/webauthn?invitation=TOKEN
4. Invited user visits link
5. POST /api/v1/webauthn/registration/begin {username, invitation_token}
6. WebAuthn ceremony
7. POST /api/v1/webauthn/registration/finish
8. TenantUserService.RegisterInvitedUser():
   - Validate invitation (not expired, pending)
   - Set user.TenantID = invitation.TenantID
   - Set user.IsTenantOwner = false
   - Assign role from invitation
   - Mark invitation accepted
9. Issue JWT with tenant_id claim
10. Redirect to /protected
```

---

## Testing Strategy

### Test Pyramid

```
         /\
        /  \  E2E UI (Playwright) - Critical user journeys
       /----\
      /      \  Integration Tests - API + DB + multi-protocol
     /--------\
    /          \  Unit Tests - Entities, Services, Handlers
   /--------------\
```

### Coverage Goals

| Layer | Target | Focus | Status |
|-------|--------|-------|--------|
| Entities | 100% | All methods, edge cases | COMPLETE |
| DAO | 90%+ | CRUD, queries, error handling | COMPLETE |
| Services | 90%+ | Business logic, authorization | COMPLETE |
| Handlers | 85%+ | Request/response, validation | COMPLETE |
| Integration | Critical paths | Registration, invitation, isolation | COMPLETE |
| E2E UI | User journeys | Happy path + key error cases | COMPLETE (182 tests) |

### CI Pipeline

```yaml
# Suggested workflow
jobs:
  backend-unit:
    - go test ./pkg/...

  backend-integration:
    - docker-compose up -d
    - INTEGRATION_TEST=1 go test ./test/integration/...

  frontend-unit:
    - npm run lint
    - npm run typecheck

  frontend-e2e:
    - npx playwright install
    - npm run test:e2e
```

---

## Key Design Decisions

1. **Tenant per user by default**: New registrations create new tenants (like Stripe/AWS)
2. **Invitation-based team building**: Users join existing tenants via invitation only
3. **Reuse TenantManager**: Leverage existing `pkg/tenant/manager.go` for tenant lifecycle
4. **QuicBaaS OIDC tokens**: Use IAM service for token issuance, not local JWT
5. **One-time tokens**: Invitation tokens are cryptographically secure, single-use
6. **Playwright for E2E**: Industry-standard, excellent WebAuthn support
7. **WebAuthn mocking**: Virtual authenticator for headless CI testing

---

## Verification Checklist

### Backend
- [x] Unit tests pass: `go test ./pkg/store/datastore/entities/... ./pkg/platform/service/...`
- [x] Handler tests pass: `go test ./pkg/webservice/v1/...`
- [x] Integration tests pass: `INTEGRATION_TEST=1 go test ./test/integration/...`
- [x] New user creates tenant in QuicBaaS
- [x] Invited user joins existing tenant
- [x] JWT contains tenant_id claim
- [x] Authorization blocks cross-tenant access
- [x] Multi-protocol API tests pass (REST, gRPC)

### Frontend
- [x] Playwright E2E tests pass: `npm run test:e2e` (182 passing, 14 skipped)
- [x] New user registration flow works (existing WebAuthn)
- [x] Invited user registration flow works
- [x] Invitation admin page works
- [x] Tenant context persists correctly
- [x] Logout clears all state

### Documentation
- [x] All new docs created and linked
- [x] Existing docs updated
- [x] API reference complete
- [x] Testing guide complete

### SDKs
- [x] Go SDK complete
- [x] JavaScript SDK complete

---

## Implementation Order

### Day 0: Project Consolidation - COMPLETE
- [x] Move `go-trusted-platform-web` to `go-trusted-platform/web/`
- [x] Update Makefile with web targets
- [x] Update Makefile to use local web/ directory (remove external repo references)
- [x] Verify frontend still builds and runs

### Week 1: Core Backend - COMPLETE
- [x] Entity layer (user.go, invitation.go, registration.go)
- [x] DAO layer (invitation DAO)
- [x] Service layer (invitation service, tenant_user service)
- [x] Unit tests for all above

### Week 2: API + Integration - COMPLETE
- [x] API handlers (webauthn update, invitation handler)
- [x] Middleware (tenant context)
- [x] Handler tests
- [x] Backend integration tests

### Week 3: Frontend - COMPLETE
- [x] Playwright setup
- [x] AuthContext provider
- [x] WebAuthn page updates
- [x] Invitation admin page
- [x] Frontend E2E tests (182 passing)

### Week 4: Docs + Polish - COMPLETE
- [x] All documentation updates (backend)
- [x] Frontend E2E testing complete
- [x] Code review and cleanup

---

## Progress Log

| Date | Phase | Completed | Notes |
|------|-------|-----------|-------|
| 2026-01-18 | Planning | Plan created | Monorepo decision made |
| 2026-01-18 | Phase 0 | Monorepo consolidation | Frontend moved to web/, Makefiles updated |
| 2026-01-19 | Phase 1A | Entity Layer | User, Invitation, Registration entities complete |
| 2026-01-19 | Phase 1B | DAO Layer | InvitationDAO interface and implementation complete |
| 2026-01-19 | Phase 1C | Service Layer | InvitationService, TenantUserService, UserService complete |
| 2026-01-19 | Phase 1D | API Layer | WebAuthn handler, Invitation handler, router, gRPC proto complete |
| 2026-01-20 | Phase 1G-1H | Backend Tests | Unit and integration tests complete |
| 2026-01-20 | Phase 1I | Documentation | IAM, Auth, Tenant docs complete |
| 2026-01-20 | Phase 1J | SDKs | Go and JavaScript SDKs complete |
| 2026-01-21 | Phase 1E | Frontend | AuthContext, invitation page, tenant dashboard complete |
| 2026-01-21 | Phase 1F | E2E Tests | Playwright setup, 182 tests passing (auth, invitations, tenant, isolation) |
| 2026-01-21 | COMPLETE | Phase 1 | All backend, frontend, tests, and documentation complete |
