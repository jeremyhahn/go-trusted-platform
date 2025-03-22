FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Fix for libc-bin on ARM 32-bit architecture
RUN rm /var/lib/dpkg/info/libc-bin.* && \
    apt-get clean && \
    apt-get update && \
    apt-get install -y libc-bin

RUN apt-get install -y \
    isc-dhcp-server \
    tftpd-hpa \
    nfs-kernel-server \
    pxelinux \
    syslinux-common \
    apache2 \
    curl \
    rsync \
    iproute2 \
    net-tools \
    iputils-ping \
    traceroute \
    tcpdump \
    dnsutils \
    telnet \
    vim \
    wget \
    supervisor \
    pxelinux \
    libc-bin \
    curl \
    build-essential \
    libssl-dev \
    pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/sbin/dhcpd /usr/sbin/isc-dhcp-server && \
    touch /var/lib/dhcp/dhcpd.leases && \
    chown dhcpd:dhcpd /var/lib/dhcp/dhcpd.leases & \
    echo "Checking ISC DHCP Server installation" && \
    dpkg -l isc-dhcp-server || echo "isc-dhcp-server not installed" && \
    which isc-dhcp-server || echo "isc-dhcp-server not found in path"

RUN mkdir -p /srv/tftp/pxelinux.cfg /var/www/html/isos

# /usr/lib/syslinux/modules/bios/menu.c32
# /usr/lib/syslinux/modules/efi64/menu.c32
# /usr/lib/syslinux/modules/efi32/menu.c32

# /usr/lib/syslinux/modules/bios/libutil.c32
# /usr/lib/syslinux/modules/efi64/libutil.c32
# /usr/lib/syslinux/modules/efi32/libutil.c32

# Copy syslinux files and copy them to TFTP directory
RUN apt-get update && apt-get install -y syslinux-common && \
    cp /usr/lib/PXELINUX/pxelinux.0 /srv/tftp/ && \
    cp /usr/lib/syslinux/modules/bios/ldlinux.c32 /srv/tftp/ && \
    cp /usr/lib/syslinux/modules/bios/menu.c32 /srv/tftp/ && \
    cp /usr/lib/syslinux/modules/bios/libutil.c32 /srv/tftp/ && \
    cp /usr/lib/syslinux/modules/bios/libcom32.c32 /srv/tftp/ && \
    echo "Syslinux boot files copied."

# Configure Apache to serve ISOs
RUN echo "<VirtualHost *:80>" > /etc/apache2/sites-available/000-default.conf && \
    echo "    DocumentRoot /var/www/html" >> /etc/apache2/sites-available/000-default.conf && \
    echo "    <Directory /var/www/html>" >> /etc/apache2/sites-available/000-default.conf && \
    echo "        Options Indexes FollowSymLinks" >> /etc/apache2/sites-available/000-default.conf && \
    echo "        AllowOverride None" >> /etc/apache2/sites-available/000-default.conf && \
    echo "        Require all granted" >> /etc/apache2/sites-available/000-default.conf && \
    echo "    </Directory>" >> /etc/apache2/sites-available/000-default.conf && \
    echo "</VirtualHost>" >> /etc/apache2/sites-available/000-default.conf

# Configure ISC DHCP server
RUN echo "default-lease-time 600;" > /etc/dhcp/dhcpd.conf && \
    echo "max-lease-time 7200;" >> /etc/dhcp/dhcpd.conf && \
    echo "allow booting;" >> /etc/dhcp/dhcpd.conf && \
    echo "subnet 192.168.50.0 netmask 255.255.255.0 {" >> /etc/dhcp/dhcpd.conf && \
    echo "  range 192.168.50.150 192.168.50.253;" >> /etc/dhcp/dhcpd.conf && \
    echo "  option broadcast-address 192.168.50.255;" >> /etc/dhcp/dhcpd.conf && \
    echo "  option routers 192.168.50.1;" >> /etc/dhcp/dhcpd.conf && \
    echo "  option domain-name-servers 8.8.8.8;" >> /etc/dhcp/dhcpd.conf && \
    echo "  next-server 192.168.50.100;" >> /etc/dhcp/dhcpd.conf && \
    echo "  filename \"pxelinux.0\";" >> /etc/dhcp/dhcpd.conf && \
    echo "}" >> /etc/dhcp/dhcpd.conf

# Copy supervisord config to container
# COPY ./supervisord.conf /etc/supervisord.conf

EXPOSE 69/udp 80 2049

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
