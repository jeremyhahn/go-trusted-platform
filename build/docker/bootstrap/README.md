# platform-pxeboot

The bootstrap container: the `pxeboot` binary (`cmd/pxeboot`, DHCP + TFTP +
HTTP) plus Samba for BMC virtual media, run together under supervisord. It is
the network boot server `platformctl bootstrap run` deploys onto a provisioning
host.

This is **not** the legacy `build/docker/pxe-server` image. That one is a
separate artifact with its own release wiring; nothing here builds or deploys
it.

## Build

```bash
make pxeboot-container   # builds bin/pxeboot, then platform-pxeboot:latest and :<version>
make netboot-media       # the media sets the container serves (bin/netboot-media)
```

No installer media is baked into the image. Every media set it serves, x86_64
included, comes from a `make netboot-media` build that the deployer stages
under `/data/media` (`deployer.netboot_media_dir` in bootstrap.yaml).

## Deploy

Deploy it with `platformctl bootstrap run`, never with a hand-written
`docker run` line. The deployer writes the manifest and per-node configs into
the data directory, stages the netboot media, passes every `BOOTSTRAP_*`
setting from bootstrap.yaml, and checks a running container against the
config before it reuses it. A hand-started container skips all of that. See
[docs/bootstrap/user.md](../../../docs/bootstrap/user.md) and the deployer keys
in [docs/bootstrap/engineering.md](../../../docs/bootstrap/engineering.md).

The container runs with `--net=host`: DHCP and TFTP must see the provisioning
VLAN's broadcast traffic directly.

## Ports

| Port | Service | When |
|------|---------|------|
| 67/udp | DHCP (full, or proxy with `proxy_dhcp`) | always |
| 69/udp | TFTP — iPXE firmware | always |
| 8080/tcp | HTTP — media sets, boot scripts, per-MAC config (`bootstrap_http_port`) | always |
| HTTP port + 1 | per-device boot script server (`bootstrap_device_script_port`) | always |
| 137/udp, 138/udp, 139/tcp, 445/tcp | Samba `[boot]` share over `/data` | used only by BMC virtual media |
| 10809/tcp | NBD root volumes | only with a `diskless-nbd` node in the manifest |

Nothing listens on port 80.

## Volumes

| Host path | Container path | Lifetime |
|-----------|----------------|----------|
| `deployer.data_dir` | `/data` | manifest, configs, media, install logs; removed by teardown |
| `deployer.firmware_cache_dir` (default `<data_dir>-firmware`) | `/var/cache/go-trusted-platform/firmware` | boot-node mode only; never removed by the deployer |

Without boot-node mode the firmware cache lives inside the container and is
downloaded again from `boot.ipxe.org` by each new container.

## DHCP router option

`entrypoint.sh` sources `pxeboot-env.sh`, which applies the `BOOTSTRAP_*`
defaults and assembles the optional `pxeboot` flags. DHCP advertises
`BOOTSTRAP_GATEWAY` (default `192.0.2.1`) as the router. On an isolated VLAN
whose boot server does not route, `deployer.bootstrap_no_router: true` sets
`BOOTSTRAP_NO_ROUTER=true`: no `--dhcp-gateway` reaches `pxeboot`, so offers
and acks carry no router option. The deployer refuses `bootstrap_no_router`
together with `bootstrap_gateway`, and the entrypoint exits 2 on the same pair.

## Privileges

DHCP and TFTP bind UDP 67 and 69, so `pxeboot` needs root or
`CAP_NET_BIND_SERVICE` (plus `CAP_NET_RAW` for the raw-socket DHCP path). In
this image supervisord and `pxeboot` run as root, which covers both.

## Boot-node mode

By default the container lives for one bootstrap: Phase 7 waits for the
cluster health gate and then removes it.

`deployer.boot_node: true` makes it a long-running boot server, for a host that
keeps serving a netboot VLAN:

- `docker run` gets `--restart unless-stopped`, so it comes back with the host;
- Phase 7 neither removes the container nor deletes `data_dir`;
- the firmware cache is the host volume above, so the server keeps working
  offline once the firmware is cached;
- a re-run of `platformctl bootstrap run` that redeploys (`redeploy_mode:
  always`, or a container that no longer matches the config under the default
  `if-stale`) replaces only the container and keeps both volumes; a running
  container that matches is left as it is. `if-stale` compares the image, the
  volumes and the restart policy, not the `BOOTSTRAP_*` environment, so after
  changing a DHCP setting force the replacement with `redeploy_mode: always`;
- `platformctl bootstrap teardown` still removes the container and `data_dir`,
  and leaves the firmware cache.

`data_dir` and `firmware_cache_dir` must be absolute, must not be under `/tmp`,
`/run` or `/dev/shm`, and must not overlap. Setting `firmware_cache_dir`
without `boot_node` is an error.

[`configs/bootstrap/edge-01-vlan405.example.yaml`](../../../configs/bootstrap/edge-01-vlan405.example.yaml)
is a boot node with no router: edge-01 serving the Raspberry Pi rack on VLAN 405,
netbooting the Pis diskless, with platformd standalone on edge-01 as their
control plane until the CM4 is proven.
