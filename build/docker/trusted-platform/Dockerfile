ARG BASE_IMAGE="ubuntu:latest"

FROM $BASE_IMAGE

LABEL maintainer="jeremyhahn <mail@jeremyhahn.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        --no-install-recommends \
        --reinstall ca-certificates

COPY --from=trusted_platform_builder /trusted-platform/tpadm /trusted-platform/tpadm

ENTRYPOINT ["/platform"]
