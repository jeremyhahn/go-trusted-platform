# trusted-platform-builder

This is the `builder` for the Trusted Platform software. The resulting image contains a build environment with necessary dependencies and platform binaries.

# Build

The following command produces an image with the platform binaries output to the BUILD_DIR, which defaults to `/builder`.

    docker build --load -t trusted-platform-builder
