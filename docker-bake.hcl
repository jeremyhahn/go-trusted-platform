group "amd64" {
  targets = [
    "trusted-platform-builder-debian-amd64",
    "trusted-platform-builder-alpine-amd64"
  ]
}

group "arm64" {
  targets = [
    "trusted-platform-builder-debian-arm64",
    "trusted-platform-builder-alpine-arm64"
  ]
}

target "trusted-platform-builder-debian-amd64" {
  context    = "."
  dockerfile = "build/docker/trusted-platform-builder/Dockerfile-debian"
  platforms  = ["linux/amd64"]
  tags       = ["trusted-platform-builder-debian:amd64"]
  args = {
    UDEV_RULES  = "build/docker/trusted-platform-builder/70-u2f.rules"
    ENTRY_POINT = "build/docker/trusted-platform-builder/entrypoint.sh"
  }
}

target "trusted-platform-builder-debian-arm64" {
  context    = "."
  dockerfile = "build/docker/trusted-platform-builder/Dockerfile-debian"
  platforms  = ["linux/arm64"]
  tags       = ["trusted-platform-builder-debian:arm64"]
  args = {
    UDEV_RULES  = "build/docker/trusted-platform-builder/70-u2f.rules"
    ENTRY_POINT = "build/docker/trusted-platform-builder/entrypoint.sh"
  }
}

target "trusted-platform-builder-alpine-amd64" {
  context    = "."
  dockerfile = "build/docker/trusted-platform-builder/Dockerfile-alpine"
  platforms  = ["linux/amd64"]
  tags       = ["trusted-platform-builder-alpine:amd64"]
  args = {
    UDEV_RULES  = "build/docker/trusted-platform-builder/70-u2f.rules"
    ENTRY_POINT = "build/docker/trusted-platform-builder/entrypoint.sh"
  }
}

target "trusted-platform-builder-alpine-arm64" {
  context    = "."
  dockerfile = "build/docker/trusted-platform-builder/Dockerfile-alpine"
  platforms  = ["linux/arm64"]
  tags       = ["trusted-platform-builder-alpine:arm64"]
  args = {
    UDEV_RULES  = "build/docker/trusted-platform-builder/70-u2f.rules"
    ENTRY_POINT = "build/docker/trusted-platform-builder/entrypoint.sh"
  }
}
