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

// Package tpm provides a client for TPM service operations.
package tpm

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/quotebind"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to TPM service operations.
type Client struct {
	grpc platformv1.TPMServiceClient
}

// NewClient creates a new TPM service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewTPMServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new TPM service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.TPMServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Info returns TPM capabilities and information.
func (c *Client) Info(ctx context.Context) (*platformv1.TPMInfoResponse, error) {
	resp, err := c.grpc.Info(ctx, &platformv1.TPMInfoRequest{})
	if err != nil {
		return nil, &ErrInfoFailed{Cause: err}
	}
	return resp, nil
}

// Provision initializes the TPM with required keys.
func (c *Client) Provision(ctx context.Context, req *platformv1.TPMProvisionRequest) (*platformv1.TPMProvisionResponse, error) {
	resp, err := c.grpc.Provision(ctx, req)
	if err != nil {
		return nil, &ErrProvisionFailed{Cause: err}
	}
	return resp, nil
}

// Clear clears the TPM (requires owner authorization).
func (c *Client) Clear(ctx context.Context, ownerPassword string, confirm bool) error {
	_, err := c.grpc.Clear(ctx, &platformv1.TPMClearRequest{
		OwnerPassword: ownerPassword,
		Confirm:       confirm,
	})
	if err != nil {
		return &ErrClearFailed{Cause: err}
	}
	return nil
}

// EK Operations

// CreateEK creates an Endorsement Key.
func (c *Client) CreateEK(ctx context.Context, attributes *platformv1.KeyAttributes, persistent bool) (*platformv1.CreateEKResponse, error) {
	resp, err := c.grpc.CreateEK(ctx, &platformv1.CreateEKRequest{
		Attributes: attributes,
		Persistent: persistent,
	})
	if err != nil {
		return nil, &ErrCreateEKFailed{Cause: err}
	}
	return resp, nil
}

// GetEK retrieves the Endorsement Key.
func (c *Client) GetEK(ctx context.Context, algorithm platformv1.KeyAlgorithm, handle uint32) (*platformv1.GetEKResponse, error) {
	resp, err := c.grpc.GetEK(ctx, &platformv1.GetEKRequest{
		Algorithm: algorithm,
		Handle:    handle,
	})
	if err != nil {
		return nil, &ErrGetEKFailed{Cause: err}
	}
	return resp, nil
}

// GetEKCertificate retrieves the EK certificate.
func (c *Client) GetEKCertificate(ctx context.Context, algorithm platformv1.KeyAlgorithm, handle uint32) (*platformv1.GetEKCertificateResponse, error) {
	resp, err := c.grpc.GetEKCertificate(ctx, &platformv1.GetEKCertificateRequest{
		Algorithm: algorithm,
		Handle:    handle,
	})
	if err != nil {
		return nil, &ErrGetEKCertFailed{Cause: err}
	}
	return resp, nil
}

// ImportEKCertificate imports an EK certificate.
func (c *Client) ImportEKCertificate(ctx context.Context, certificate []byte, format string, nvramIndex uint32) error {
	_, err := c.grpc.ImportEKCertificate(ctx, &platformv1.ImportEKCertificateRequest{
		Certificate: certificate,
		Format:      format,
		NvramIndex:  nvramIndex,
	})
	if err != nil {
		return &ErrImportEKCertFailed{Cause: err}
	}
	return nil
}

// DeleteEK deletes the Endorsement Key.
func (c *Client) DeleteEK(ctx context.Context, handle uint32, algorithm platformv1.KeyAlgorithm, password string) error {
	_, err := c.grpc.DeleteEK(ctx, &platformv1.DeleteEKRequest{
		Handle:    handle,
		Algorithm: algorithm,
		Password:  password,
	})
	if err != nil {
		return &ErrDeleteEKFailed{Cause: err}
	}
	return nil
}

// SRK Operations

// CreateSRK creates a Storage Root Key.
func (c *Client) CreateSRK(ctx context.Context, attributes *platformv1.KeyAttributes, persistent bool, parentHandle uint32, parentPassword string) (*platformv1.CreateSRKResponse, error) {
	resp, err := c.grpc.CreateSRK(ctx, &platformv1.CreateSRKRequest{
		Attributes:     attributes,
		Persistent:     persistent,
		ParentHandle:   parentHandle,
		ParentPassword: parentPassword,
	})
	if err != nil {
		return nil, &ErrCreateSRKFailed{Cause: err}
	}
	return resp, nil
}

// GetSRK retrieves the Storage Root Key.
func (c *Client) GetSRK(ctx context.Context, algorithm platformv1.KeyAlgorithm, handle uint32) (*platformv1.GetSRKResponse, error) {
	resp, err := c.grpc.GetSRK(ctx, &platformv1.GetSRKRequest{
		Algorithm: algorithm,
		Handle:    handle,
	})
	if err != nil {
		return nil, &ErrGetSRKFailed{Cause: err}
	}
	return resp, nil
}

// DeleteSRK deletes the Storage Root Key.
func (c *Client) DeleteSRK(ctx context.Context, handle uint32, algorithm platformv1.KeyAlgorithm, password string) error {
	_, err := c.grpc.DeleteSRK(ctx, &platformv1.DeleteSRKRequest{
		Handle:    handle,
		Algorithm: algorithm,
		Password:  password,
	})
	if err != nil {
		return &ErrDeleteSRKFailed{Cause: err}
	}
	return nil
}

// AK Operations

// CreateAK creates an Attestation Key.
func (c *Client) CreateAK(ctx context.Context, attributes *platformv1.KeyAttributes, persistent bool, parentHandle uint32, parentPassword string) (*platformv1.CreateAKResponse, error) {
	resp, err := c.grpc.CreateAK(ctx, &platformv1.CreateAKRequest{
		Attributes:     attributes,
		Persistent:     persistent,
		ParentHandle:   parentHandle,
		ParentPassword: parentPassword,
	})
	if err != nil {
		return nil, &ErrCreateAKFailed{Cause: err}
	}
	return resp, nil
}

// GetAK retrieves the Attestation Key.
func (c *Client) GetAK(ctx context.Context, algorithm platformv1.KeyAlgorithm, handle uint32) (*platformv1.GetAKResponse, error) {
	resp, err := c.grpc.GetAK(ctx, &platformv1.GetAKRequest{
		Algorithm: algorithm,
		Handle:    handle,
	})
	if err != nil {
		return nil, &ErrGetAKFailed{Cause: err}
	}
	return resp, nil
}

// DeleteAK deletes the Attestation Key.
func (c *Client) DeleteAK(ctx context.Context, handle uint32, algorithm platformv1.KeyAlgorithm, password string) error {
	_, err := c.grpc.DeleteAK(ctx, &platformv1.DeleteAKRequest{
		Handle:    handle,
		Algorithm: algorithm,
		Password:  password,
	})
	if err != nil {
		return &ErrDeleteAKFailed{Cause: err}
	}
	return nil
}

// Seal/Unseal Operations

// Seal seals data to the TPM.
func (c *Client) Seal(ctx context.Context, req *platformv1.SealRequest) (*platformv1.SealResponse, error) {
	resp, err := c.grpc.Seal(ctx, req)
	if err != nil {
		return nil, &ErrSealFailed{Cause: err}
	}
	return resp, nil
}

// Unseal unseals data from the TPM.
func (c *Client) Unseal(ctx context.Context, req *platformv1.UnsealRequest) ([]byte, error) {
	resp, err := c.grpc.Unseal(ctx, req)
	if err != nil {
		return nil, &ErrUnsealFailed{Cause: err}
	}
	return resp.Data, nil
}

// Attestation Operations

// Quote generates a TPM quote over nonce bound to the connection the call
// travels on (#482): the daemon quotes SHA-256(nonce || channel_binding)
// and echoes channel_binding, and the response is returned only if both
// match the binding this end derives. A quote relayed from another
// connection is refused with *quotebind.ErrQuoteNotBound; transports with
// no TLS 1.3 connection refuse the call.
func (c *Client) Quote(ctx context.Context, akHandle uint32, akPassword string, pcrIndices []uint32, pcrBank platformv1.PCRBank, nonce []byte) (*platformv1.QuoteResponse, error) {
	var capture quotebind.Capture
	resp, err := c.grpc.Quote(ctx, &platformv1.QuoteRequest{
		AkHandle:   akHandle,
		AkPassword: akPassword,
		PcrIndices: pcrIndices,
		PcrBank:    pcrBank,
		Nonce:      nonce,
	}, capture.Option())
	if err != nil {
		return nil, &ErrQuoteFailed{Cause: err}
	}
	if err := capture.CheckEcho(nonce, resp.GetChannelBinding(), resp.GetQuote()); err != nil {
		return nil, &ErrQuoteFailed{Cause: err}
	}
	return resp, nil
}

// VerifyQuote verifies a TPM quote. For a quote Quote returned, set
// channel_binding to the binding it echoed: the daemon then expects
// SHA-256(nonce || channel_binding). Set signature_algorithm to the scheme
// the quote declared: the signature is checked under it, and a request
// without it fails verification.
func (c *Client) VerifyQuote(ctx context.Context, req *platformv1.VerifyQuoteRequest) (*platformv1.VerifyQuoteResponse, error) {
	resp, err := c.grpc.VerifyQuote(ctx, req)
	if err != nil {
		return nil, &ErrVerifyQuoteFailed{Cause: err}
	}
	return resp, nil
}

// GetEventLog retrieves the TPM event log.
func (c *Client) GetEventLog(ctx context.Context, format string) (*platformv1.GetEventLogResponse, error) {
	resp, err := c.grpc.GetEventLog(ctx, &platformv1.GetEventLogRequest{Format: format})
	if err != nil {
		return nil, &ErrGetEventLogFailed{Cause: err}
	}
	return resp, nil
}

// GetPCRs retrieves PCR values.
func (c *Client) GetPCRs(ctx context.Context, indices []uint32, bank platformv1.PCRBank) ([]*platformv1.PCRValue, error) {
	resp, err := c.grpc.GetPCRs(ctx, &platformv1.GetPCRsRequest{
		Indices: indices,
		Bank:    bank,
	})
	if err != nil {
		return nil, &ErrGetPCRsFailed{Cause: err}
	}
	return resp.PcrValues, nil
}

// NVRAM Operations

// DefineNVRAM defines an NVRAM space.
func (c *Client) DefineNVRAM(ctx context.Context, index, size uint32, password string, attributes []string) error {
	_, err := c.grpc.DefineNVRAM(ctx, &platformv1.DefineNVRAMRequest{
		Index:      index,
		Size:       size,
		Password:   password,
		Attributes: attributes,
	})
	if err != nil {
		return &ErrDefineNVRAMFailed{Index: index, Cause: err}
	}
	return nil
}

// WriteNVRAM writes data to NVRAM.
func (c *Client) WriteNVRAM(ctx context.Context, index uint32, data []byte, password string, offset uint32) error {
	_, err := c.grpc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{
		Index:    index,
		Data:     data,
		Password: password,
		Offset:   offset,
	})
	if err != nil {
		return &ErrWriteNVRAMFailed{Index: index, Cause: err}
	}
	return nil
}

// ReadNVRAM reads data from NVRAM.
func (c *Client) ReadNVRAM(ctx context.Context, index uint32, password string, offset, size uint32) ([]byte, error) {
	resp, err := c.grpc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{
		Index:    index,
		Password: password,
		Offset:   offset,
		Size:     size,
	})
	if err != nil {
		return nil, &ErrReadNVRAMFailed{Index: index, Cause: err}
	}
	return resp.Data, nil
}

// UndefineNVRAM removes an NVRAM space.
func (c *Client) UndefineNVRAM(ctx context.Context, index uint32, password string) error {
	_, err := c.grpc.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{
		Index:    index,
		Password: password,
	})
	if err != nil {
		return &ErrUndefineNVRAMFailed{Index: index, Cause: err}
	}
	return nil
}

// GetRandom generates cryptographically secure random bytes.
func (c *Client) GetRandom(ctx context.Context, numBytes uint32) ([]byte, error) {
	resp, err := c.grpc.GetRandom(ctx, &platformv1.GetRandomRequest{NumBytes: numBytes})
	if err != nil {
		return nil, &ErrGetRandomFailed{Cause: err}
	}
	return resp.RandomBytes, nil
}
