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

package appsvc

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// objectColumns are the listing columns every object list prints.
var objectColumns = []protoreflect.Name{"key", "size", "content_type", "version", "status", "modified_at_unix_ms"}

// NewObjectStorageCommand creates the objectstorage command group.
func NewObjectStorageCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "objectstorage",
		Short: "Store, read, copy and list objects",
		Long: `Store, read, copy and list the objects of the object storage service.

Keys take the form NAMESPACE:NAME. On this release a put or copy must name the
backend that stores the object with --backend.

Examples:
  # Store a file, tagged, with three replicas
  platformctl objectstorage put docs:report.pdf --file report.pdf --backend default \
      --content-type application/pdf --tag env=prod --min-replicas 3

  platformctl objectstorage head docs:report.pdf
  platformctl objectstorage get docs:report.pdf -o json
  platformctl objectstorage list --prefix docs: --limit 20
  platformctl objectstorage list-by-tag env prod
  platformctl objectstorage list-tenant acme
  platformctl objectstorage copy docs:report.pdf archive:report.pdf --backend default
  platformctl objectstorage delete docs:report.pdf`,
	}

	cmd.AddCommand(
		newObjectPutCommand(getFlags),
		newObjectGetCommand(getFlags),
		newObjectKeyCommand(getFlags, "delete KEY", "Delete an object", "failed to delete the object",
			func(key, tenant string) *platformv1.DeleteObjectRequest {
				return &platformv1.DeleteObjectRequest{Key: key, TenantId: tenant}
			},
			platformv1.ObjectStorageServiceClient.DeleteObject,
			fieldsTable[*platformv1.DeleteObjectResponse]),
		newObjectKeyCommand(getFlags, "head KEY", "Show the metadata of an object without its data",
			"failed to get the object metadata",
			func(key, tenant string) *platformv1.HeadObjectRequest {
				return &platformv1.HeadObjectRequest{Key: key, TenantId: tenant}
			},
			platformv1.ObjectStorageServiceClient.HeadObject,
			fieldsTable[*platformv1.HeadObjectResponse]),
		newObjectListCommand(getFlags),
		newObjectCopyCommand(getFlags),
		newObjectListByTagCommand(getFlags),
		newObjectListTenantCommand(getFlags),
	)
	return cmd
}

// objectListTable renders a listing page.
func objectListTable(reply *platformv1.ListObjectsResponse) *cli.TableData {
	return listTable(reply.GetObjects(), objectColumns...)
}

// putOptions are the flags of `objectstorage put`.
type putOptions struct {
	file            string
	contentType     string
	tenant          string
	shard           uint64
	tags            map[string]string
	backend         string
	minReplicas     int32
	replicationMode string
	targetStores    []string
	archiveAfter    int32
	archiveStore    string
	retentionDays   int32
	maxVersions     int32
}

func newObjectPutCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &putOptions{}
	cmd := newCommand(getFlags, "put KEY [DATA]", "Store an object from DATA or --file", cobra.RangeArgs(1, 2),
		func(flags *cli.CommonFlags, args []string) error {
			value, err := opts.value(args[1:])
			if err != nil {
				return err
			}
			return call(flags, newObjectStorageClient, "failed to store the object",
				platformv1.ObjectStorageServiceClient.PutObject, opts.request(args[0], value),
				fieldsTable[*platformv1.PutObjectResponse])
		})
	f := cmd.Flags()
	f.StringVar(&opts.file, "file", "", "read the object data from this file instead of DATA")
	f.StringVar(&opts.contentType, "content-type", "", "MIME type of the object")
	addTenantFlag(f, &opts.tenant)
	f.Uint64Var(&opts.shard, "shard", 0, "shard that stores the object (default chosen by the service)")
	f.StringToStringVar(&opts.tags, "tag", nil, "tag as key=value; repeatable")
	f.StringVar(&opts.backend, "backend", "", "backend that stores the object (required by the service)")
	f.Int32Var(&opts.minReplicas, "min-replicas", 0, "replicate to at least this many stores")
	f.StringVar(&opts.replicationMode, "replication-mode", "", "replication mode: sync|async|quorum")
	f.StringSliceVar(&opts.targetStores, "replica-store", nil, "store that holds a replica; repeatable")
	f.Int32Var(&opts.archiveAfter, "archive-after-days", 0, "archive the object after this many days")
	f.StringVar(&opts.archiveStore, "archive-store", "", "store the object is archived to")
	f.Int32Var(&opts.retentionDays, "retention-days", 0, "keep the object for this many days")
	f.Int32Var(&opts.maxVersions, "max-versions", 0, "versions of the object kept")
	return cmd
}

// value is the object data: DATA when given, else the --file contents.
// Exactly one of them names the data.
func (o *putOptions) value(data []string) ([]byte, error) {
	if (len(data) == 1) == (o.file != "") {
		return nil, ErrObjectData{}
	}
	if o.file == "" {
		return []byte(data[0]), nil
	}
	value, err := os.ReadFile(o.file)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read --file " + quote(o.file), Err: err}
	}
	return value, nil
}

// request builds the put request. A policy is sent only when one of its
// flags is set.
func (o *putOptions) request(key string, value []byte) *platformv1.PutObjectRequest {
	request := &platformv1.PutObjectRequest{
		Key:           key,
		Value:         value,
		ContentType:   o.contentType,
		TenantId:      o.tenant,
		ShardId:       o.shard,
		Tags:          o.tags,
		TargetBackend: o.backend,
	}
	if o.minReplicas != 0 || o.replicationMode != "" || len(o.targetStores) != 0 {
		request.ReplicationPolicy = &platformv1.ObjectReplicationPolicy{
			Enabled: true, MinReplicas: o.minReplicas, Mode: o.replicationMode, TargetStores: o.targetStores,
		}
	}
	if o.archiveAfter != 0 || o.archiveStore != "" {
		request.ArchivePolicy = &platformv1.ObjectArchivePolicy{
			Enabled: true, ArchiveAfterDays: o.archiveAfter, TargetStore: o.archiveStore,
		}
	}
	if o.retentionDays != 0 || o.maxVersions != 0 {
		request.RetentionPolicy = &platformv1.ObjectRetentionPolicy{
			Enabled: true, RetentionDays: o.retentionDays, MaxVersions: o.maxVersions,
		}
	}
	return request
}

func newObjectGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	var metadata bool
	cmd := newCommand(getFlags, "get KEY", "Show an object with its data", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			return call(flags, newObjectStorageClient, "failed to get the object",
				platformv1.ObjectStorageServiceClient.GetObject,
				&platformv1.GetObjectRequest{Key: args[0], TenantId: tenant, IncludeMetadata: metadata},
				fieldsTable[*platformv1.GetObjectResponse])
		})
	addTenantFlag(cmd.Flags(), &tenant)
	cmd.Flags().BoolVar(&metadata, "metadata", false, "include the tags and timestamps")
	return cmd
}

// newObjectKeyCommand creates a command that names one object by its key,
// optionally scoped to a tenant.
func newObjectKeyCommand[Q, R proto.Message](getFlags func() *cli.CommonFlags, use, short, failure string,
	request func(key, tenant string) Q,
	rpc func(platformv1.ObjectStorageServiceClient, context.Context, Q, ...grpc.CallOption) (R, error),
	table func(R) *cli.TableData) *cobra.Command {
	var tenant string
	cmd := newCommand(getFlags, use, short, cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			return call(flags, newObjectStorageClient, failure, rpc, request(args[0], tenant), table)
		})
	addTenantFlag(cmd.Flags(), &tenant)
	return cmd
}

// pageOptions are the paging flags every object list shares.
type pageOptions struct {
	limit  int32
	cursor string
}

func addPageFlags(f *pflag.FlagSet, opts *pageOptions) {
	f.Int32Var(&opts.limit, "limit", 0, "most objects per page (default chosen by the service)")
	f.StringVar(&opts.cursor, "cursor", "", "cursor of the page to start at, from a previous listing")
}

func addTenantFlag(f *pflag.FlagSet, tenant *string) {
	f.StringVar(tenant, "tenant", "", "tenant that owns the object")
}

func newObjectListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var prefix, tenant string
	var tags bool
	page := &pageOptions{}
	cmd := newCommand(getFlags, "list", "List the objects under a key prefix", cobra.NoArgs,
		func(flags *cli.CommonFlags, _ []string) error {
			return call(flags, newObjectStorageClient, "failed to list the objects",
				platformv1.ObjectStorageServiceClient.ListObjects,
				&platformv1.ListObjectsRequest{Prefix: prefix, TenantId: tenant, Limit: page.limit, Cursor: page.cursor, IncludeTags: tags},
				objectListTable)
		})
	f := cmd.Flags()
	f.StringVar(&prefix, "prefix", "", "list only keys that start with this prefix")
	addTenantFlag(f, &tenant)
	f.BoolVar(&tags, "tags", false, "include each object's tags")
	addPageFlags(f, page)
	return cmd
}

func newObjectCopyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant, backend string
	var overwrite bool
	cmd := newCommand(getFlags, "copy SOURCE DESTINATION", "Copy an object to a new key", cobra.ExactArgs(2),
		func(flags *cli.CommonFlags, args []string) error {
			return call(flags, newObjectStorageClient, "failed to copy the object",
				platformv1.ObjectStorageServiceClient.CopyObject,
				&platformv1.CopyObjectRequest{
					SourceKey: args[0], DestinationKey: args[1], TenantId: tenant,
					OverwriteExisting: overwrite, TargetBackend: backend,
				},
				fieldsTable[*platformv1.CopyObjectResponse])
		})
	f := cmd.Flags()
	addTenantFlag(f, &tenant)
	f.StringVar(&backend, "backend", "", "backend that stores the copy (required by the service)")
	f.BoolVar(&overwrite, "overwrite", false, "replace an object already at DESTINATION")
	return cmd
}

func newObjectListByTagCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	page := &pageOptions{}
	cmd := newCommand(getFlags, "list-by-tag TAG VALUE", "List the objects whose tag has a value", cobra.ExactArgs(2),
		func(flags *cli.CommonFlags, args []string) error {
			return call(flags, newObjectStorageClient, "failed to list the objects by tag",
				platformv1.ObjectStorageServiceClient.ListObjectsByTag,
				&platformv1.ListObjectsByTagRequest{
					TagName: args[0], TagValue: args[1], TenantId: tenant, Limit: page.limit, Cursor: page.cursor,
				},
				objectListTable)
		})
	addTenantFlag(cmd.Flags(), &tenant)
	addPageFlags(cmd.Flags(), page)
	return cmd
}

func newObjectListTenantCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tags bool
	page := &pageOptions{}
	cmd := newCommand(getFlags, "list-tenant TENANT", "List the objects one tenant owns", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			return call(flags, newObjectStorageClient, "failed to list the tenant's objects",
				platformv1.ObjectStorageServiceClient.ListTenantObjects,
				&platformv1.ListTenantObjectsRequest{TenantId: args[0], Limit: page.limit, Cursor: page.cursor, IncludeTags: tags},
				objectListTable)
		})
	cmd.Flags().BoolVar(&tags, "tags", false, "include each object's tags")
	addPageFlags(cmd.Flags(), page)
	return cmd
}
