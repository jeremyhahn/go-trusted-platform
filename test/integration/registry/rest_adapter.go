//go:build integration

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

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/registry"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	// restImagesPath is the platformd REST registry surface
	// (pkg/webservice/v1/rest/registry/router.go).
	restImagesPath = "/api/v1/compute/images"

	// restImageContentType is the JSON image envelope PushImage accepts and
	// GetImage returns when asked for it in Accept.
	restImageContentType = "application/x-trusted-platform-image"

	// Push metadata travels in these headers (PushImage).
	headerRepository = "X-Trusted-Platform-Repository"
	headerTag        = "X-Trusted-Platform-Tag"
	headerEncrypt    = "X-Trusted-Platform-Encrypt"
	headerOverwrite  = "X-Trusted-Platform-Overwrite"
)

// ErrRESTStatus is returned when platformd answers a REST call with an
// error status.
type ErrRESTStatus struct {
	Operation  string
	StatusCode int
	Message    string
}

func (e ErrRESTStatus) Error() string {
	return fmt.Sprintf("REST %s failed (%d): %s", e.Operation, e.StatusCode, e.Message)
}

// RESTAdapter implements RegistryCommands against platformd's
// /api/v1/compute/images routes over mTLS.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup builds the mTLS client and checks the registry surface answers.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint, err := helpers.RequireEndpoint(helpers.EnvRESTEndpoint)
	if err != nil {
		return err
	}
	r.baseURL = strings.TrimRight(endpoint, "/")
	r.httpClient = helpers.NewHTTPClient(DefaultCommandTimeout)

	if _, err := r.Status(ctx); err != nil {
		return ErrAdapterConnectionFailed{Adapter: "REST", URL: r.baseURL, Err: err}
	}
	return nil
}

// Teardown cleans up REST client resources.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// do sends one request and returns the status code and body.
func (r *RESTAdapter) do(req *http.Request) (int, []byte, error) {
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// call sends a JSON request and decodes the response envelope's payload
// into out. A 404 becomes ErrImageNotFound for ref.
func (r *RESTAdapter) call(ctx context.Context, op, method, path, ref string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	status, body, err := r.do(req)
	if err != nil {
		return err
	}
	return decodeEnvelope(op, ref, status, body, out)
}

// decodeEnvelope unwraps the platform's {code, error, success, payload}
// response envelope.
func decodeEnvelope(op, ref string, status int, body []byte, out interface{}) error {
	var envelope struct {
		Error   string          `json:"error"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		if status != http.StatusOK {
			return ErrRESTStatus{Operation: op, StatusCode: status, Message: string(body)}
		}
		return ErrInvalidResponse{Operation: op, Err: err}
	}
	if status == http.StatusNotFound {
		return ErrImageNotFound{Reference: ref}
	}
	if status != http.StatusOK {
		return ErrRESTStatus{Operation: op, StatusCode: status, Message: envelope.Error}
	}
	if out == nil || len(envelope.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Payload, out); err != nil {
		return ErrInvalidResponse{Operation: op, Err: err}
	}
	return nil
}

// imagePath is the route of one image reference.
func imagePath(ref string) string {
	return restImagesPath + "/" + ref
}

// Push posts the JSON image envelope with its repository and tag headers.
func (r *RESTAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	payload, err := pushEnvelope(opts)
	if err != nil {
		return nil, err
	}
	repository, tag := splitImageRef(ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+restImagesPath, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", restImageContentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set(headerRepository, repository)
	req.Header.Set(headerTag, tag)
	if opts.Encrypt {
		req.Header.Set(headerEncrypt, "true")
	}
	if opts.AllowOverwrite {
		req.Header.Set(headerOverwrite, "true")
	}
	status, body, err := r.do(req)
	if err != nil {
		return nil, err
	}

	var resp grpcapi.RegistryPushResponse
	if err := decodeEnvelope(opPush, ref, status, body, &resp); err != nil {
		return nil, err
	}
	result := &PushResult{Reference: ref, Size: resp.BytesReceived, PushedAt: resp.Timestamp}
	if resp.Artifact != nil {
		result.Digest = resp.Artifact.Digest
	}
	return result, nil
}

// Pull asks GetImage for the image envelope and decodes it.
func (r *RESTAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+imagePath(ref), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", restImageContentType)
	status, body, err := r.do(req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, decodeEnvelope(opPull, ref, status, body, nil)
	}

	var img registry.Image
	if err := json.Unmarshal(body, &img); err != nil {
		return nil, ErrInvalidResponse{Operation: opPull, Err: err}
	}
	result := &PullResult{
		Reference: ref,
		Manifest:  fromRegistryManifest(ref, img.Manifest),
		Config:    img.Config,
		PulledAt:  time.Now().UTC(),
	}
	for _, l := range img.Layers {
		result.Layers = append(result.Layers, LayerData{MediaType: l.MediaType, Content: l.Content})
	}
	return result, nil
}

// List calls ListImages. The REST surface pages by offset, so the cursor
// is the offset of the next page.
func (r *RESTAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	offset := 0
	if opts.Cursor != "" {
		n, err := strconv.Atoi(opts.Cursor)
		if err != nil || n < 0 {
			return nil, ErrInvalidArgument{Argument: "cursor", Reason: "REST cursor is a non-negative offset"}
		}
		offset = n
	}
	query := url.Values{}
	if opts.Repository != "" {
		query.Set("repository", opts.Repository)
	}
	if opts.Limit > 0 {
		query.Set("limit", strconv.Itoa(opts.Limit))
	}
	if offset > 0 {
		query.Set("offset", strconv.Itoa(offset))
	}
	path := restImagesPath
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	var resp restregistry.ListImagesResponse
	if err := r.call(ctx, opList, http.MethodGet, path, "", &resp); err != nil {
		return nil, err
	}
	result := &ListResult{TotalCount: resp.Total}
	for _, img := range resp.Images {
		result.Images = append(result.Images, fromImageSummary(img))
	}
	if next := offset + len(resp.Images); len(resp.Images) > 0 && next < resp.Total {
		result.HasMore = true
		result.NextCursor = strconv.Itoa(next)
	}
	return result, nil
}

// fromImageSummary converts a ListImages entry.
func fromImageSummary(s restregistry.ImageSummary) ImageManifest {
	m := ImageManifest{
		MediaType:   s.MediaType,
		Reference:   s.Repository + ":" + s.Tag,
		Digest:      s.Digest,
		Size:        s.Size,
		Annotations: s.Annotations,
	}
	if t, err := time.Parse(time.RFC3339, s.CreatedAt); err == nil {
		m.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, s.UpdatedAt); err == nil {
		m.UpdatedAt = t
	}
	return m
}

// Delete calls DeleteImage.
func (r *RESTAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	var resp grpcapi.RegistryDeleteResponse
	if err := r.call(ctx, opDelete, http.MethodDelete, imagePath(ref), ref, &resp); err != nil {
		return nil, err
	}
	return &DeleteResult{Reference: ref, Digest: resp.Digest, DeletedAt: resp.Timestamp}, nil
}

// Inspect calls GetImage for the JSON artifact detail.
func (r *RESTAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	var detail grpcapi.RegistryArtifactDetail
	if err := r.call(ctx, opInspect, http.MethodGet, imagePath(ref), ref, &detail); err != nil {
		return nil, err
	}
	if detail.Artifact == nil {
		return nil, ErrInvalidResponse{Operation: opInspect, Err: ErrImageNotFound{Reference: ref}}
	}
	a := detail.Artifact
	manifest := ImageManifest{
		Reference:   ref,
		Digest:      a.Digest,
		Size:        a.Size,
		Annotations: a.Annotations,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
	return &InspectResult{Reference: ref, Manifest: &manifest, TotalSize: a.Size}, nil
}

// Status calls the registry status route.
func (r *RESTAdapter) Status(ctx context.Context) (*StatusResult, error) {
	var resp grpcapi.RegistryStatusResponse
	if err := r.call(ctx, opStatus, http.MethodGet, restImagesPath+"/status", "", &resp); err != nil {
		return nil, err
	}
	healthy := resp.Health == grpcapi.RegistryHealthStatusHealthy
	result := &StatusResult{
		Healthy: healthy,
		Status:  "degraded",
		Version: resp.Version,
	}
	if resp.Storage != nil {
		result.ImageCount = int(resp.Storage.ArtifactCount)
		result.TotalSize = resp.Storage.UsedBytes
	}
	if healthy {
		result.Status = "running"
	}
	if !resp.StartedAt.IsZero() && !resp.Timestamp.IsZero() {
		result.Uptime = resp.Timestamp.Sub(resp.StartedAt)
	}
	return result, nil
}

// Tag has no REST route.
func (r *RESTAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, noSurface(r.Name(), opTag)
}

// VerifyClient has no REST route.
func (r *RESTAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, noSurface(r.Name(), opVerifyClient)
}

// GetSession has no REST route.
func (r *RESTAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, noSurface(r.Name(), opGetSession)
}

// InvalidateSession has no REST route.
func (r *RESTAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return noSurface(r.Name(), opInvalidateSession)
}

// EncryptImage has no REST route.
func (r *RESTAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, noSurface(r.Name(), opEncryptImage)
}

// DecryptImage has no REST route.
func (r *RESTAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, noSurface(r.Name(), opDecryptImage)
}
