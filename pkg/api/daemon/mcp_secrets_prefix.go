package daemon

import (
	"context"
	"math"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

// SecretsPrefixService is the prefix listing the secret_get_by_prefix MCP tool
// calls: the gRPC SecretsManagement GetSecretsByPrefix, so MCP answers what
// gRPC answers for the same request.
type SecretsPrefixService interface {
	GetSecretsByPrefix(ctx context.Context, req *pb.GetSecretsByPrefixRequest) (*pb.GetSecretsByPrefixResponse, error)
}

// Compile-time check: the gRPC secrets adapter serves the MCP prefix tool.
var _ SecretsPrefixService = (*SecretsServerAdapter)(nil)

// SetSecretsPrefixService wires the gRPC secrets adapter into the
// secret_get_by_prefix tool.
func (p *MCPServiceProvider) SetSecretsPrefixService(svc SecretsPrefixService) {
	p.secretsPrefix = svc
}

// SecretGetByPrefix lists the secrets whose ID starts with prefix, with their
// data when includeData is set, through the gRPC GetSecretsByPrefix call.
func (p *MCPServiceProvider) SecretGetByPrefix(ctx context.Context, prefix string, includeData bool, limit int, cursor string) (interface{}, error) {
	if p.secretsPrefix == nil {
		return nil, ErrServiceNotAvailable{Service: "secrets"}
	}
	if prefix == "" {
		return nil, ErrKMSInvalidParameter{Parameter: "prefix", Reason: "secret prefix is required"}
	}
	if limit < 0 || limit > math.MaxInt32 {
		return nil, ErrKMSInvalidParameter{Parameter: "limit", Reason: "limit must be between 0 and 2147483647"}
	}

	resp, err := p.secretsPrefix.GetSecretsByPrefix(ctx, &pb.GetSecretsByPrefixRequest{
		Prefix:      prefix,
		IncludeData: includeData,
		Limit:       int32(limit),
		Cursor:      cursor,
	})
	if err != nil {
		return nil, ErrSecretsOperationFailed{Operation: "GetSecretsByPrefix", Cause: err}
	}
	return resp, nil
}
