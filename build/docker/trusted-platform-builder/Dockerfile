ARG BASE_IMAGE="ubuntu:latest"

FROM $BASE_IMAGE AS trusted_platform_builder

LABEL maintainer="jeremyhahn <mail@jeremyhahn.com>"

ARG BUILD_DIR=/trusted-platform/build/lib
ARG ENTRY_POINT=build/docker/trusted-platform-builder/entrypoint.sh
ARG OPENSSL=openssl-3.3
ARG TPM2_TSS_TAG=4.1.3
ARG TPM2_ABRMD_TAG=3.0.0
ARG TPM2_TOOLS_TAG=5.7
ARG OPENSC_TAG=0.25.1
ARG SOFTHSM_TAG=2.6.1
ARG TPM2_PKCS11_TAG=1.9.0
ARG YUBICO_PIV_TOOL_TAG=yubico-piv-tool-2.5.2
ARG TPM2_PYTSS=2.3.0
ARG TP_TAG=v0.0.1-alpha.1

ENV DEBIAN_FRONTEND=noninteractive
ENV TPM2TOOLS_TCTI=mssim:host=localhost,port=2321

SHELL ["/bin/bash", "-c"]

WORKDIR $BUILD_DIR

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        --no-install-recommends \
        --reinstall ca-certificates \
        vim \
        autoconf \
        build-essential \
        git \
        cmake \
        libtool \
        libssl-dev \
        pkg-config \
        check \
        libpcsclite-dev \
        gengetopt \
        help2man \
        zlib1g-dev \ 
        pcscd \
        autoconf-archive \
        libcmocka0 \
        libcmocka-dev \
        procps \
        iproute2 \
        gcc \
        automake \
        uthash-dev \
        doxygen \
        libjson-c-dev \
        libini-config-dev \
        libcurl4-openssl-dev \
        uuid-dev \
        libltdl-dev \
        libusb-1.0-0-dev \
        libftdi-dev \
        python3-yaml \
        libglib2.0-dev \
        wget \
        libsqlite3-dev \
        sqlite3 \
        pandoc \
        libcppunit-dev \
        libyaml-dev \
        python3-dev \
        python3-pip \
        python3.12-venv \
        python3-pyasn1-modules \
        python3-cryptography \
        python3-tpm2-pytss \
        libtss2-tcti-tabrmd-dev \
        yubikey-manager \
        libu2f-udev && \
        echo "*\t-\tmemlock\tunlimited" > /etc/security/limits.conf

# RUN git clone --depth=1 --branch $OPENSSL https://github.com/openssl/openssl.git && \
#     openssl && \
#     ./Configure \
#     make -j$(nproc) && \
#     make -j$(nproc) install && \
#     ldconfig

RUN git clone --depth=1 --branch $TPM2_TSS_TAG https://github.com/tpm2-software/tpm2-tss.git && \
    cd tpm2-tss && \
    ./bootstrap && \
    ./configure --with-udevrulesprefix && \
    make -j$(nproc) && \
    make -j$(nproc) install && \
    ldconfig

RUN git clone --depth=1 --branch $TPM2_ABRMD_TAG https://github.com/tpm2-software/tpm2-abrmd.git && \
    cd tpm2-abrmd && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make -j$(nproc) install && \
    ldconfig 

RUN git clone --depth=1 --branch $TPM2_TOOLS_TAG https://github.com/tpm2-software/tpm2-tools.git && \
    cd tpm2-tools && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make -j$(nproc) install && \
    make check && \
    ldconfig

RUN mkdir ibmtpm && \
    cd ibmtpm && \
    wget https://sourceforge.net/projects/ibmswtpm2/files/latest/download -O ibmtpm.tar.gz && \
    tar -zxvf ibmtpm.tar.gz && \
    cd src && \
    make -j$(nproc) && \
    make -j$(nproc) install && \
    ldconfig

RUN git clone --depth=1 --branch $OPENSC_TAG https://github.com/OpenSC/OpenSC.git && \
    cd OpenSC && \
    ./bootstrap && \
    ./configure && \
    make -j$($nproc) && \
    make -j$(nproc) install && \
    ldconfig

RUN git clone --depth=1 --branch $SOFTHSM_TAG https://github.com/opendnssec/SoftHSMv2.git && \
    cd SoftHSMv2 && \
    ./autogen.sh || true && \
    ./autogen.sh && \
    ./configure --with-objectstore-backend-db && \
    make -j$(nproc) && \
    make -j$(nproc) install && \
#    make check && \
    ldconfig

#ENV PATH="/trusted-platform/tpm2-tools/tools:/trusted-platform/tpm2-pkcs11/tools:/trusted-platform/ibmtpm/src:$PATH"
RUN git clone --depth=1 --branch $TPM2_PKCS11_TAG https://github.com/tpm2-software/tpm2-pkcs11.git && \
    cd tpm2-pkcs11 && \
    ./bootstrap && \
        git clone --depth=1 --branch $TPM2_PYTSS https://github.com/tpm2-software/tpm2-pytss && \
            cd tpm2-pytss && \
            python3 -m venv venv && \
            source ./venv/bin/activate && \
            pip install pyasn1_modules && \
            pip install -e . && \
            ../../tpm2-pkcs11/configure --with-fapi --enable-unit && \
            make -j$(nproc) && \
            make -j$(nproc) install && \
            # make check && \
            ldconfig

RUN git clone --depth=1 --branch $YUBICO_PIV_TOOL_TAG https://github.com/Yubico/yubico-piv-tool.git && \
    cd yubico-piv-tool && \
    mkdir build &&  \
    cd build && \
    # cmake ../ -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc
    cmake .. -DOPENSSL_STATIC_LINK=ON && \
    cmake --build . && \
    make -j$(nproc) && \
    make -j$(nproc) install  && \
    ldconfig

RUN git clone --depth=1 --branch $TP_TAG https://github.com/jeremyhahn/go-trusted-platform.git && \
    cd go-trusted-platform && \
    make

COPY --chown=root:root --chmod=755 $ENTRY_POINT /usr/local/bin/entrypoint.sh

COPY build/docker/trusted-platform-builder/70-u2f.rules /etc/udev/rules.d/70-u2f.rules

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# FROM scratch AS libs
# COPY --from=stage1 /usr/local/lib/libykpiv.so ./libykpiv.so
# COPY --from=stage1 /usr/local/bin/yubico-piv-tool ./yubico-piv-tool
