# trusted-platform

This is the runtime container for the Trusted Platform software.

# Build

The included `Makefile` provides targets to build and run the platform runtime containers.

# Makefile

### Variables

| Variable Name | Description                                          | Default Value                                          |
|---------------|------------------------------------------------------|-------------------------------------------------------|
| `CONFIG`      | Path to the Trusted Platform configuration file. | `../../../configs/platform/local/server/config.yaml`  |


### Targets

| Target Name   | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `local-server`| Starts the platform as a server using the "local" server configuration.    |
| `local-client`| Starts the platform as a client using the "local" configuration file.      |
| `clean`       | Cleans up the build, runtime volumes, and/or other created artifacts.      |

