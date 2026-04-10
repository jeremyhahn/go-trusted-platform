# Trusted Platform Network File System Server

This is an NFS server that can be used to host ISO's for PXE booting, Linux rootfs netboot systems, common file server, and more.

The included `Makefile` can be used to build the NFS server. Simply run the default `make` target to build a local nfs-server container.

# Build

## Targets

| **Target**    | **Description**                                                                                                                                                                                                                                                |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `default`     | Runs the sequence of targets: `clean`, `init`, `build`, `run`, and `mount` to set up, run, and mount the NFS server.                                                                                                                                        |
| `init`        | Initializes the environment by creating the required directories (`data` and `mnt`) and creating a test file (`data/test.txt`).                                                                                                                               |
| `build`       | Builds the Docker image for the NFS server with the tag `nfs-server` using the `--load` option (enabling multi-platform support).                                                                                                                             |
| `push`        | Builds and pushes the Docker image to a Docker registry using the tag `jeremyhahn/nfs-server`.                                                                                                                                                                |
| `run`         | Cleans any existing container and then runs the NFS server container in detached mode with privileged access, mounting the local `data` directory to `/exports` in the container.                                                                       |
| `get-ip`      | Retrieves the IP address of the running NFS server container by inspecting its network settings. The IP is saved to a file named `.nfs_server_ip`.                                                                                                            |
| `wait-for-nfs`| Waits until the NFS server is ready by repeatedly checking the export list with `showmount -e` against the stored IP address.                                                                                                                                  |
| `mount`       | Depends on `get-ip` and `wait-for-nfs`. Creates (or ensures) the mount directory (`mnt`) exists, mounts the NFS share (`<IP>:/exports`) to the local `mnt` directory using `sudo mount`, and lists the contents of the mounted directory.         |
| `clean`       | Cleans up the environment by force unmounting the mount point (`mnt`), removing the Docker container (`nfs-server`), and deleting the `data`, `mnt` directories and the `.nfs_server_ip` file.                                                      |
