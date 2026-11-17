// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// servicePEP is an iam.PEPClient fake that answers from a test
// AuthorizationService, so tests written against an AuthorizationService
// fake drive the unscoped path, which the IAM PEP decides (SPEC row 116,
// #1995). The service sees the PEP subject's ID as its subject.
type servicePEP struct {
	svc AuthorizationService
}

func (p servicePEP) Check(ctx context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error) {
	if p.svc == nil {
		return nil, errors.New("no authorization service")
	}
	allowed, err := p.svc.CheckPermission(ctx, req.Subject.ID, req.Resource, req.Action)
	if err != nil {
		return nil, err
	}
	return &iam.CheckResponse{Allowed: allowed}, nil
}

func (p servicePEP) CheckBatch(context.Context, *iam.CheckBatchRequest) (*iam.CheckBatchResponse, error) {
	return nil, errors.New("not used")
}

// pepCaller is mgr, or the legacyCaller when mgr is nil; a mockAuthManager
// without claims gets the legacyCaller's, so its token names a subject.
func pepCaller(mgr AuthManager) AuthManager {
	if mgr == nil {
		return legacyCaller()
	}
	if m, ok := mgr.(*mockAuthManager); ok && m.getClaimsFunc == nil {
		m.getClaimsFunc = legacyCaller().getClaimsFunc
	}
	return mgr
}

// tokenSubject is a bool-only AuthManager whose token's subject is the token
// itself, so a test can see which token reached the PEP.
func tokenSubject() *mockAuthManager {
	return &mockAuthManager{
		getClaimsFunc: func(_ context.Context, token string) (map[string]interface{}, error) {
			return map[string]interface{}{"sub": token}, nil
		},
	}
}

// pepChecker builds a checker whose unscoped path asks svc through the PEP.
func pepChecker(svc AuthorizationService, mgr AuthManager) *AuthorizationChecker {
	return NewAuthorizationChecker(svc, pepCaller(mgr), WithPEPClient(servicePEP{svc}))
}

// usePEP sets the authorization of s to svc and mgr with svc behind the PEP.
func usePEP(s *Server, svc AuthorizationService, mgr AuthManager) {
	s.SetAuthorizationService(svc, pepCaller(mgr))
	s.authChecker.pep = servicePEP{svc}
}
