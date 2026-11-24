# syntax=docker/dockerfile:1
#
# vBMC: virtual BMC responder for integration tests.

FROM golang:1.27.4-bookworm AS build

WORKDIR /src

# The full module tree: vbmc imports a few pkg/* helper types.
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

# Liveness: the image has no curl or wget.

ENTRYPOINT ["/usr/local/bin/vbmc"]
