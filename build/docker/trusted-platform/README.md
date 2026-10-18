# trusted-platform

This is the runtime container for the Trusted Platform software.

# Build

The included `Makefile` builds the platform runtime images. It ships no
configuration: start from a deployment profile in [`configs/platform/templates/`](../../../configs/platform/templates/README.md).

# Makefile

### Variables

| Variable Name | Description                                              | Default Value      |
|---------------|----------------------------------------------------------|--------------------|
| `APPNAME`     | Image name prefix.                                       | `trusted-platform` |
| `PLATFORMD`   | Binary name copied out of the builder images.            | `platformd`        |
| `VOLUME`      | Host directory created for the runtime `etc/log/data`.   | `./trusted-data`   |

### Targets

| Target Name    | Description                                                              |
|----------------|--------------------------------------------------------------------------|
| `default`      | `clean`, `volume`, `binaries`, `build-debian` and `build-alpine`.         |
| `volume`       | Creates `$(VOLUME)/etc`, `log` and `data`.                               |
| `binaries`     | Copies the static `platformd` binaries out of the alpine builder images. |
| `build-debian` | Builds the Debian runtime image for amd64 and arm64.                     |
| `build-alpine` | Builds the Alpine runtime image for amd64 and arm64.                     |
| `clean`        | Removes the volume and the copied binaries.                              |
