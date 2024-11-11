FROM debian:bullseye

LABEL maintainer="mail@jeremyhahn.com" \
      description="Automated Debian OS build with Docker based on Minimal Debian Based Deboostrap Linux"

ENV DEBIAN_FRONTEND=noninteractive \
    INSTALL_FOLDER=/denos \
    DISTRO_NAME=denos \
    VERSION=bullseye

ARG CONFIG_DIR=./

RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    bash \
    debootstrap \
    squashfs-tools \
    xorriso \
    syslinux \
    grub-pc-bin \
    grub-efi-amd64-bin \
    qemu-system-x86 \
    wget \
    build-essential \
    dialog \
    apt-utils \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${INSTALL_FOLDER}

ADD https://github.com/dinooz/denos.git ${INSTALL_FOLDER}

RUN chmod -R +x ${INSTALL_FOLDER}/*.sh

SHELL ["/bin/bash", "-c"]

RUN ./01_denos_pre_reqs.sh

COPY ${CONFIG_DIR}denos_config.txt ${INSTALL_FOLDER}/denos_config.txt

RUN ./02_denos_debootstrap.sh
RUN  echo -e "debian\ndebian" | ./03_denos_chroot_docker.sh && exit
RUN ./04_denos_MakeSquashfs.sh
RUN ./05_denos_BiosUEFI_ISO.sh

CMD [ "/bin/bash" ]
