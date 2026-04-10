#!/bin/bash

# Start NFS services
rpcbind
service nfs-kernel-server start

# Keep the container running
exec tail -f /dev/null

