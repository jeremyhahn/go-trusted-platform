# syntax=docker/dockerfile:1
#
# vBMC -- Virtual BMC responder for integration tests.
# Multi-stage build: compile statically, run on scratch with TLS
# roots baked in from the build stage.

FROM golang:1.26-bookworm AS build

WORKDIR /src

# Copy the full module tree because the vbmc binary transitively
# imports pkg/* for a few helper types (via go-trusted-platform). A
# minimal copy is possible but fragile; copying the repo keeps the
# build reproducible.
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

RUN go build -trimpath -ldflags="-s -w" -o /out/vbmc ./test/integration/bmc/vbmc/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/vbmc /usr/local/bin/vbmc

USER nonroot:nonroot
EXPOSE 8443

ENV VBMC_HTTPS_ADDR=:8443 \
    VBMC_VENDOR=Supermicro \
    VBMC_LOG_LEVEL=info

# Liveness: the image has no curl/wget. Integration harness uses
# an external probe; this HEALTHCHECK is intentionally omitted.

ENTRYPOINT ["/usr/local/bin/vbmc"]
