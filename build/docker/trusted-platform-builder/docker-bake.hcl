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
  dockerfile = "Dockerfile-debian"
  platforms  = ["linux/amd64"]
  tags       = ["trusted-platform-builder-debian:latest-amd64"]
  args = {
    UDEV_RULES  = "70-u2f.rules"
    ENTRY_POINT = "entrypoint.sh"
  }
}

target "trusted-platform-builder-debian-arm64" {
  context    = "."
  dockerfile = "Dockerfile-debian"
  platforms  = ["linux/arm64"]
  tags       = ["trusted-platform-builder-debian:latest-arm64"]
  args = {
    UDEV_RULES  = "70-u2f.rules"
    ENTRY_POINT = "entrypoint.sh"
  }
}

target "trusted-platform-builder-alpine-amd64" {
  context    = "."
  dockerfile = "Dockerfile-alpine"
  platforms  = ["linux/amd64"]
  tags       = ["trusted-platform-builder-alpine:latest-amd64"]
  args = {
    UDEV_RULES  = "70-u2f.rules"
    ENTRY_POINT = "entrypoint.sh"
  }
}

target "trusted-platform-builder-alpine-arm64" {
  context    = "."
  dockerfile = "Dockerfile-alpine"
  platforms  = ["linux/arm64"]
  tags       = ["trusted-platform-builder-alpine:latest-arm64"]
  args = {
    UDEV_RULES  = "70-u2f.rules"
    ENTRY_POINT = "entrypoint.sh"
  }
}
