// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

package objectstorage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strconv"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// CLIAdapter drives the object storage service through `platformctl
// objectstorage` in a local context (the Unix socket).
type CLIAdapter struct {
	binaryPath string
	configDir  string
	configPath string
}

// NewCLIAdapter returns an unconnected CLI adapter.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns the transport name.
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup finds platformctl and writes a local context for it.
func (c *CLIAdapter) Setup(context.Context) error {
	binaryPath := platformCTLPath()
	if _, err := exec.LookPath(binaryPath); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.binaryPath = binaryPath

	dir, path, err := helpers.WriteTempLocalCLIConfig(helpers.GetSocketPath(), helpers.GetGRPCEndpoint())
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.configDir = dir
	c.configPath = path
	return nil
}

// Teardown removes the CLI context and any object data files.
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	err := os.RemoveAll(c.configDir)
	c.configDir = ""
	c.configPath = ""
	return err
}

// run executes platformctl with JSON output and decodes the reply into out.
func (c *CLIAdapter) run(ctx context.Context, out proto.Message, args ...string) error {
	full := []string{"--config", c.configPath, "--context", helpers.CLIContextName}
	full = append(full, args...)
	full = append(full, "--output", "json")

	cmd := exec.CommandContext(ctx, c.binaryPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return ErrCLICommandFailed{Args: full, Output: output, Err: err}
	}
	if err := protojson.Unmarshal(stdout.Bytes(), out); err != nil {
		return ErrCLIDecodeFailed{Args: full, Output: stdout.String(), Err: err}
	}
	return nil
}

// Put stores an object, passing the data through --file so it reaches the
// service byte for byte.
func (c *CLIAdapter) Put(ctx context.Context, req *platformv1.PutObjectRequest) (*platformv1.PutObjectResponse, error) {
	file, err := os.CreateTemp(c.configDir, "object-*")
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(req.GetValue())
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return nil, errors.Join(err, os.Remove(file.Name()))
	}

	args := []string{"objectstorage", "put", req.GetKey(), "--file", file.Name()}
	args = appendString(args, "--backend", req.GetTargetBackend())
	args = appendString(args, "--content-type", req.GetContentType())
	args = appendString(args, "--tenant", req.GetTenantId())
	args = appendTags(args, req.GetTags())
	resp := &platformv1.PutObjectResponse{}
	runErr := c.run(ctx, resp, args...)
	return resp, errors.Join(runErr, os.Remove(file.Name()))
}

// Get reads an object.
func (c *CLIAdapter) Get(ctx context.Context, req *platformv1.GetObjectRequest) (*platformv1.GetObjectResponse, error) {
	args := []string{"objectstorage", "get", req.GetKey()}
	args = appendString(args, "--tenant", req.GetTenantId())
	args = appendBool(args, "--metadata", req.GetIncludeMetadata())
	resp := &platformv1.GetObjectResponse{}
	return resp, c.run(ctx, resp, args...)
}

// Head reads the metadata of an object.
func (c *CLIAdapter) Head(ctx context.Context, req *platformv1.HeadObjectRequest) (*platformv1.HeadObjectResponse, error) {
	args := []string{"objectstorage", "head", req.GetKey()}
	args = appendString(args, "--tenant", req.GetTenantId())
	resp := &platformv1.HeadObjectResponse{}
	return resp, c.run(ctx, resp, args...)
}

// List lists objects by key prefix.
func (c *CLIAdapter) List(ctx context.Context, req *platformv1.ListObjectsRequest) (*platformv1.ListObjectsResponse, error) {
	args := []string{"objectstorage", "list"}
	args = appendString(args, "--prefix", req.GetPrefix())
	args = appendString(args, "--tenant", req.GetTenantId())
	args = appendBool(args, "--tags", req.GetIncludeTags())
	args = appendPage(args, req.GetLimit(), req.GetCursor())
	resp := &platformv1.ListObjectsResponse{}
	return resp, c.run(ctx, resp, args...)
}

// Copy copies an object.
func (c *CLIAdapter) Copy(ctx context.Context, req *platformv1.CopyObjectRequest) (*platformv1.CopyObjectResponse, error) {
	args := []string{"objectstorage", "copy", req.GetSourceKey(), req.GetDestinationKey()}
	args = appendString(args, "--backend", req.GetTargetBackend())
	args = appendString(args, "--tenant", req.GetTenantId())
	args = appendBool(args, "--overwrite", req.GetOverwriteExisting())
	resp := &platformv1.CopyObjectResponse{}
	return resp, c.run(ctx, resp, args...)
}

// ListByTag lists the objects carrying a tag.
func (c *CLIAdapter) ListByTag(ctx context.Context, req *platformv1.ListObjectsByTagRequest) (*platformv1.ListObjectsResponse, error) {
	args := []string{"objectstorage", "list-by-tag", req.GetTagName(), req.GetTagValue()}
	args = appendString(args, "--tenant", req.GetTenantId())
	args = appendPage(args, req.GetLimit(), req.GetCursor())
	resp := &platformv1.ListObjectsResponse{}
	return resp, c.run(ctx, resp, args...)
}

// Delete removes an object.
func (c *CLIAdapter) Delete(ctx context.Context, req *platformv1.DeleteObjectRequest) (*platformv1.DeleteObjectResponse, error) {
	args := []string{"objectstorage", "delete", req.GetKey()}
	args = appendString(args, "--tenant", req.GetTenantId())
	resp := &platformv1.DeleteObjectResponse{}
	return resp, c.run(ctx, resp, args...)
}

// appendString adds a string flag when the request sets it.
func appendString(args []string, flag, value string) []string {
	if value == "" {
		return args
	}
	return append(args, flag, value)
}

// appendBool adds a boolean flag when the request sets it.
func appendBool(args []string, flag string, value bool) []string {
	if !value {
		return args
	}
	return append(args, flag)
}

// appendPage adds the paging flags the request sets.
func appendPage(args []string, limit int32, cursor string) []string {
	if limit != 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(limit), 10))
	}
	return appendString(args, "--cursor", cursor)
}

// appendTags adds one --tag flag per tag, in key order so a failure reads the
// same on every run.
func appendTags(args []string, tags map[string]string) []string {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--tag", key+"="+tags[key])
	}
	return args
}
