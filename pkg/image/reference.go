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

package image

import (
	"regexp"
	"strings"
)

// Reference parsing regular expressions
var (
	// digestRegex matches a valid digest in the format algorithm:hex
	digestRegex = regexp.MustCompile(`^[a-z0-9]+(?:\+[a-z0-9]+)?:[a-f0-9]+$`)

	// tagRegex matches a valid tag
	tagRegex = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
)

// ParseReference parses an image reference string into an ImageReference.
// Supported formats:
//   - registry.example.com/repo/image:tag
//   - registry.example.com/repo/image@sha256:digest
//   - repo/image:tag (defaults to docker.io)
//   - image:tag (defaults to docker.io/library/)
//   - image (defaults to docker.io/library/:latest)
func ParseReference(ref string) (*ImageReference, error) {
	if ref == "" {
		return nil, ErrInvalidImageReference{Reason: "empty reference"}
	}

	// Trim whitespace
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, ErrInvalidImageReference{Reason: "empty reference"}
	}

	result := &ImageReference{}

	// Check for digest
	digestIdx := strings.LastIndex(ref, "@")
	if digestIdx != -1 {
		result.Digest = ref[digestIdx+1:]
		ref = ref[:digestIdx]

		// Validate digest format
		if !isValidDigest(result.Digest) {
			return nil, ErrInvalidDigest{Digest: result.Digest, Reason: "invalid digest format"}
		}
	}

	// Check for tag (only if no digest was specified)
	if result.Digest == "" {
		tagIdx := strings.LastIndex(ref, ":")
		// Make sure this colon is not part of the registry (port number)
		// by checking if there's a slash after it
		if tagIdx != -1 {
			afterColon := ref[tagIdx+1:]
			if !strings.Contains(afterColon, "/") {
				result.Tag = afterColon
				ref = ref[:tagIdx]

				// Validate tag format
				if !isValidTag(result.Tag) {
					return nil, ErrInvalidImageReference{Reference: result.Tag, Reason: "invalid tag format"}
				}
			}
		}
	}

	// Default tag if neither tag nor digest specified
	if result.Tag == "" && result.Digest == "" {
		result.Tag = DefaultTag
	}

	// Parse registry and repository
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {
		// Just an image name: assume docker.io/library/
		result.Registry = DefaultRegistry
		result.Repository = "library/" + parts[0]
	} else {
		// Check if first part looks like a registry
		if isRegistry(parts[0]) {
			result.Registry = parts[0]
			result.Repository = parts[1]
		} else {
			// Assume docker.io and treat as repository
			result.Registry = DefaultRegistry
			result.Repository = ref
		}
	}

	// Validate repository
	if result.Repository == "" {
		return nil, ErrInvalidImageReference{Reference: ref, Reason: "empty repository"}
	}

	return result, nil
}

// String returns the full image reference as a string.
func (r *ImageReference) String() string {
	var sb strings.Builder

	if r.Registry != "" {
		sb.WriteString(r.Registry)
		sb.WriteString("/")
	}

	sb.WriteString(r.Repository)

	if r.Digest != "" {
		sb.WriteString("@")
		sb.WriteString(r.Digest)
	} else if r.Tag != "" {
		sb.WriteString(":")
		sb.WriteString(r.Tag)
	}

	return sb.String()
}

// DigestString returns the image reference with digest (without tag).
func (r *ImageReference) DigestString() string {
	if r.Digest == "" {
		return ""
	}

	var sb strings.Builder

	if r.Registry != "" {
		sb.WriteString(r.Registry)
		sb.WriteString("/")
	}

	sb.WriteString(r.Repository)
	sb.WriteString("@")
	sb.WriteString(r.Digest)

	return sb.String()
}

// TagString returns the image reference with tag (without digest).
func (r *ImageReference) TagString() string {
	var sb strings.Builder

	if r.Registry != "" {
		sb.WriteString(r.Registry)
		sb.WriteString("/")
	}

	sb.WriteString(r.Repository)

	if r.Tag != "" {
		sb.WriteString(":")
		sb.WriteString(r.Tag)
	}

	return sb.String()
}

// WithDigest returns a copy of the reference with the specified digest.
func (r *ImageReference) WithDigest(digest string) (*ImageReference, error) {
	if !isValidDigest(digest) {
		return nil, ErrInvalidDigest{Digest: digest, Reason: "invalid digest format"}
	}

	return &ImageReference{
		Registry:   r.Registry,
		Repository: r.Repository,
		Tag:        "", // Clear tag when setting digest
		Digest:     digest,
	}, nil
}

// WithTag returns a copy of the reference with the specified tag.
func (r *ImageReference) WithTag(tag string) (*ImageReference, error) {
	if !isValidTag(tag) {
		return nil, ErrInvalidImageReference{Reference: tag, Reason: "invalid tag format"}
	}

	return &ImageReference{
		Registry:   r.Registry,
		Repository: r.Repository,
		Tag:        tag,
		Digest:     "", // Clear digest when setting tag
	}, nil
}

// SignatureTag returns the tag used for signature artifacts.
// This follows the cosign convention of replacing : and @ with -.
func (r *ImageReference) SignatureTag() string {
	if r.Digest != "" {
		// Replace sha256: prefix and use as tag
		digest := r.Digest
		if strings.HasPrefix(digest, "sha256:") {
			digest = strings.TrimPrefix(digest, "sha256:")
		} else if strings.HasPrefix(digest, "sha384:") {
			digest = strings.TrimPrefix(digest, "sha384:")
		} else if strings.HasPrefix(digest, "sha512:") {
			digest = strings.TrimPrefix(digest, "sha512:")
		}
		// Truncate to reasonable length for tag
		if len(digest) > 64 {
			digest = digest[:64]
		}
		return "sha256-" + digest + ".sig"
	}

	if r.Tag != "" {
		return r.Tag + ".sig"
	}

	return "latest.sig"
}

// Validate checks if the image reference is valid.
func (r *ImageReference) Validate() error {
	if r.Repository == "" {
		return ErrInvalidImageReference{Reason: "empty repository"}
	}

	if r.Digest != "" && !isValidDigest(r.Digest) {
		return ErrInvalidDigest{Digest: r.Digest, Reason: "invalid digest format"}
	}

	if r.Tag != "" && !isValidTag(r.Tag) {
		return ErrInvalidImageReference{Reference: r.Tag, Reason: "invalid tag format"}
	}

	return nil
}

// Equal checks if two image references are equal.
func (r *ImageReference) Equal(other *ImageReference) bool {
	if other == nil {
		return false
	}

	return r.Registry == other.Registry &&
		r.Repository == other.Repository &&
		r.Tag == other.Tag &&
		r.Digest == other.Digest
}

// isRegistry checks if a string looks like a registry hostname.
func isRegistry(s string) bool {
	// Contains a dot (domain name) or colon (port)
	if strings.Contains(s, ".") || strings.Contains(s, ":") {
		return true
	}

	// localhost is a registry
	if s == "localhost" {
		return true
	}

	return false
}

// isValidDigest checks if a digest string is valid.
func isValidDigest(digest string) bool {
	if digest == "" {
		return false
	}

	return digestRegex.MatchString(digest)
}

// isValidTag checks if a tag string is valid.
func isValidTag(tag string) bool {
	if tag == "" {
		return false
	}

	// Tags can be at most 128 characters
	if len(tag) > 128 {
		return false
	}

	return tagRegex.MatchString(tag)
}

// NormalizeReference normalizes an image reference string.
// It adds default registry and tag if missing.
func NormalizeReference(ref string) (string, error) {
	parsed, err := ParseReference(ref)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// ExtractDigestAlgorithm extracts the algorithm from a digest string.
func ExtractDigestAlgorithm(digest string) DigestAlgorithm {
	if strings.HasPrefix(digest, "sha256:") {
		return DigestSHA256
	}
	if strings.HasPrefix(digest, "sha384:") {
		return DigestSHA384
	}
	if strings.HasPrefix(digest, "sha512:") {
		return DigestSHA512
	}
	return ""
}

// ExtractDigestHex extracts the hex portion from a digest string.
func ExtractDigestHex(digest string) string {
	idx := strings.Index(digest, ":")
	if idx == -1 {
		return digest
	}
	return digest[idx+1:]
}
