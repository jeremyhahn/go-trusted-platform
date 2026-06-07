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
	"context"
	"fmt"
	"sort"
	"strings"
)

// OCIDistBackend exposes the surface the OCI distribution-spec /v2/
// router needs. It is implemented by *Registry but kept as an
// interface in the rest/registry package so that package doesn't
// directly import pkg/registry/Registry — wiring crosses packages via
// the daemon command init code.
//
// The shape is intentionally narrower than the public Registry API:
// the spec speaks in (name, reference, digest) tuples and doesn't
// touch the OCI-image-as-a-whole concepts (Image, Layer) the
// platform-curated API uses.

// PutBlob persists a content-addressable blob. The digest is supplied
// by the caller and trusted (the /v2/ router does the integrity
// check before invoking this).
func (r *Registry) PutBlob(ctx context.Context, digest string, content []byte) error {
	if err := r.checkState(); err != nil {
		return err
	}
	if r.storage == nil {
		return ErrStorageNotConfigured{Op: "PutBlob"}
	}
	return r.storage.StoreBlob(ctx, digest, content)
}

// GetBlob returns the bytes at the supplied digest.
func (r *Registry) GetBlob(ctx context.Context, digest string) ([]byte, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}
	if r.storage == nil {
		return nil, ErrStorageNotConfigured{Op: "GetBlob"}
	}
	return r.storage.GetBlob(ctx, digest)
}

// BlobExists reports whether the blob is present.
func (r *Registry) BlobExists(ctx context.Context, digest string) (bool, error) {
	if err := r.checkState(); err != nil {
		return false, err
	}
	if r.storage == nil {
		return false, ErrStorageNotConfigured{Op: "BlobExists"}
	}
	return r.storage.BlobExists(ctx, digest)
}

// PutManifest persists a manifest under name:reference. The returned
// digest is the content-address of the manifest bytes themselves
// (sha256 of the raw body) — clients use this as the immutable
// reference for the artifact.
func (r *Registry) PutManifest(ctx context.Context, name, reference, mediaType string, content []byte) (string, error) {
	if err := r.checkState(); err != nil {
		return "", err
	}
	if r.storage == nil {
		return "", ErrStorageNotConfigured{Op: "PutManifest"}
	}
	digest := sha256Digest(content)
	ref := refJoin(name, reference)
	// Parse the manifest so we can store it in the platform's
	// canonical ImageManifest shape. /v2/ clients send the OCI
	// manifest JSON directly; ImageManifest is a superset that
	// matches the OCI structure for SchemaVersion=2.
	manifest, err := decodeOCIManifest(content, mediaType)
	if err != nil {
		return "", err
	}
	manifest.Reference = ref
	if err := r.storage.StoreManifest(ctx, ref, manifest); err != nil {
		return "", err
	}
	// Also store the raw manifest bytes under the digest reference so
	// GET /v2/{name}/manifests/<sha256:...> works.
	if err := r.storage.StoreManifest(ctx, refJoin(name, digest), manifest); err != nil {
		return "", err
	}
	return digest, nil
}

// GetManifest returns the manifest bytes + media type for name:reference.
func (r *Registry) GetManifest(ctx context.Context, name, reference string) (string, []byte, error) {
	if err := r.checkState(); err != nil {
		return "", nil, err
	}
	if r.storage == nil {
		return "", nil, ErrStorageNotConfigured{Op: "GetManifest"}
	}
	ref := refJoin(name, reference)
	manifest, err := r.storage.GetManifest(ctx, ref)
	if err != nil {
		return "", nil, err
	}
	body, err := encodeOCIManifest(manifest)
	if err != nil {
		return "", nil, err
	}
	mediaType := manifest.MediaType
	if mediaType == "" {
		mediaType = "application/vnd.oci.image.manifest.v1+json"
	}
	return mediaType, body, nil
}

// DeleteManifest removes a tag mapping. Blob GC happens via the
// platform-curated Delete; OCI clients expect this endpoint to be
// fast and not cascade.
func (r *Registry) DeleteManifest(ctx context.Context, name, reference string) error {
	if err := r.checkState(); err != nil {
		return err
	}
	if r.storage == nil {
		return ErrStorageNotConfigured{Op: "DeleteManifest"}
	}
	return r.storage.DeleteManifest(ctx, refJoin(name, reference))
}

// ListRepositories enumerates known repositories. We walk all
// manifests and project to the unique set of "name" prefixes.
func (r *Registry) ListRepositories(ctx context.Context, limit int) ([]string, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}
	if r.storage == nil {
		return nil, ErrStorageNotConfigured{Op: "ListRepositories"}
	}
	seen := map[string]struct{}{}
	cursor := ""
	for {
		res, err := r.storage.ListManifests(ctx, ListOptions{
			Limit:  500,
			Cursor: cursor,
		})
		if err != nil {
			return nil, err
		}
		for _, m := range res.Manifests {
			name, tag := splitOCIRef(m.Reference)
			if name == "" {
				continue
			}
			// The PutManifest path stores each manifest twice — once
			// under name:tag and once under name:sha256:<digest> — so
			// GET-by-digest works. Skip the digest-keyed copies when
			// enumerating repositories, or `alpine:sha256` shows up
			// as a phantom repo. Detected by an "sha256" tag prefix
			// followed by a 64-char hex string.
			if strings.HasSuffix(name, ":sha256") && isHex64(tag) {
				continue
			}
			seen[name] = struct{}{}
			if limit > 0 && len(seen) >= limit {
				break
			}
		}
		if !res.HasMore || res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// ListTags enumerates the tags within a repository.
func (r *Registry) ListTags(ctx context.Context, name string) ([]string, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}
	if r.storage == nil {
		return nil, ErrStorageNotConfigured{Op: "ListTags"}
	}
	res, err := r.storage.ListManifests(ctx, ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	tags := []string{}
	for _, m := range res.Manifests {
		repo, tag := splitOCIRef(m.Reference)
		if repo == name && tag != "" && !strings.HasPrefix(tag, "sha256:") {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	return tags, nil
}

// refJoin joins (name, tag) into the colon-delimited form used by
// the storage layer. If reference already encodes a digest (begins
// with sha256:) it is preserved as-is.
func refJoin(name, reference string) string {
	if reference == "" {
		return name
	}
	return name + ":" + reference
}

// splitOCIRef inverts refJoin. It uses the LAST colon as separator
// since references may contain port numbers (e.g.
// registry.example:5000/foo). The sha256: digest is treated as a
// regular tag here for storage purposes.
func splitOCIRef(ref string) (string, string) {
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == ':' {
			repo := ref[:i]
			tag := ref[i+1:]
			if strings.Contains(tag, "/") {
				return ref, ""
			}
			return repo, tag
		}
	}
	return ref, ""
}

// decodeOCIManifest parses the spec's OCI image manifest JSON into
// the platform's ImageManifest shape. Schema differences are minimal
// since ImageManifest mirrors the OCI structure.
func decodeOCIManifest(body []byte, mediaType string) (*ImageManifest, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("registry: empty manifest body")
	}
	var m ImageManifest
	if err := jsonUnmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("registry: decode manifest: %w", err)
	}
	if m.MediaType == "" {
		m.MediaType = mediaType
	}
	return &m, nil
}

// encodeOCIManifest emits the manifest in the spec's wire shape. We
// don't round-trip the original bytes because the platform mutates
// the manifest on store (CreatedAt/UpdatedAt timestamps). For
// digest-stable distribution-spec behavior we'd need to keep the
// raw push body alongside the parsed form — a follow-up if a
// content-addressed client tries to verify the manifest digest.
func encodeOCIManifest(m *ImageManifest) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("registry: nil manifest")
	}
	return jsonMarshalIndent(m)
}

// jsonUnmarshal + jsonMarshalIndent are wrappers that keep the
// stdlib imports out of this file's surface so future swaps to a
// faster encoder are a single-file change.
func jsonUnmarshal(data []byte, v interface{}) error {
	return jsonDecoder()(data, v)
}

func jsonMarshalIndent(v interface{}) ([]byte, error) {
	return jsonEncoder()(v)
}

// sha256Digest returns the canonical OCI digest string for the
// supplied bytes.
func sha256Digest(content []byte) string {
	return "sha256:" + hexSha256(content)
}

// isHex64 reports whether s is a 64-character lowercase hex string —
// the canonical encoding of a SHA-256 digest. Used to recognize
// digest-keyed manifest references during repository enumeration.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
