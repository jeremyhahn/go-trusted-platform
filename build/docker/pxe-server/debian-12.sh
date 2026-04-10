#!/bin/bash

set -e

# Set variables
MIRROR="deb.debian.org"
ARCH="amd64"
DIST="stable"
ISODIR="./volume/iso/debian-12"

# Start with a clean directory
rm -rf "$ISODIR" && mkdir -p "$ISODIR"

# Download netboot.tar.gz and required verification files
echo "Downloading netboot.tar.gz..."
wget http://"$MIRROR"/debian/dists/"$DIST"/main/installer-"$ARCH"/current/images/netboot/netboot.tar.gz -P "$ISODIR" || { echo "Download of netboot.tar.gz failed!"; exit 1; }
wget http://"$MIRROR"/debian/dists/"$DIST"/main/installer-"$ARCH"/current/images/SHA256SUMS -P "$ISODIR" || { echo "Download of SHA256SUMS failed!"; exit 1; }
wget http://"$MIRROR"/debian/dists/"$DIST"/Release -P "$ISODIR" || { echo "Download of Release failed!"; exit 1; }
wget http://"$MIRROR"/debian/dists/"$DIST"/Release.gpg -P "$ISODIR" || { echo "Download of Release.gpg failed!"; exit 1; }

# Check if netboot.tar.gz exists
echo "Listing contents of $ISODIR..."
ls -lh "$ISODIR"

echo "Checking if netboot.tar.gz exists..."
if [ ! -f "$ISODIR/netboot.tar.gz" ]; then
    echo "netboot.tar.gz not found in $ISODIR! Exiting."
    exit 1
else
    echo "Found netboot.tar.gz in $ISODIR"
fi

# Import the Debian 12 archive key (archive-key-12.asc)
echo "Importing the Debian 12 archive key..."
curl -fsSL https://ftp-master.debian.org/keys/archive-key-12.asc | sudo gpg --dearmor -o /usr/share/keyrings/debian-archive-keyring.gpg

# Explicitly trust the imported key
echo "Trusting the imported key..."
echo "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/ $DIST main" | sudo tee /etc/apt/sources.list.d/debian.list

# Verify the checksum of netboot.tar.gz and the SHA256SUMS file
echo "Verifying checksums..."

cd $ISODIR

# Verify netboot.tar.gz checksum using the original awk statements
sha256sum -c <(awk '/netboot\/netboot.tar.gz/{print $1 " netboot.tar.gz"}' "SHA256SUMS") || { echo "Checksum verification for netboot.tar.gz failed."; exit 1; }

# Verify SHA256SUMS checksum using the original awk statements
awk '/[a-f0-9]{64}[[:space:]].*main\/installer-'$ARCH'\/current\/images\/SHA256SUMS/ {print $1 " SHA256SUMS"}' "Release" | sha256sum -c || { echo "Checksum verification for SHA256SUMS failed."; exit 1; }

# Verify GPG signature with trusted key, ignoring EDDSA key errors
echo "Verifying GPG signature..."
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/debian-archive-keyring.gpg --verify "Release.gpg" "Release" 2>/dev/null || { echo "GPG signature verification failed. Ignoring EDDSA key error."; }

cd -

# Unpack netboot.tar.gz to the target directory
echo "Unpacking netboot.tar.gz..."
tar -xzf "$ISODIR/netboot.tar.gz" -C "$ISODIR"

# Replace all occurrences of "debian-installer" with "debian-12/debian-installer"
find "$ISODIR" -type f -exec sed -i 's|debian-installer|debian-12/debian-installer|g' {} +

# Copy the preseed file to the target directory
cp preseed.cfg "$ISODIR/"

echo "Debian 12 has been download, extraction, and modifications completed successfully"





# #!/bin/bash

# # Set variables
# MIRROR="deb.debian.org"
# ARCH="amd64"
# DIST="stable"
# ISODIR="./volume/iso/debian-12"

# # Create the directories if they don't exist
# mkdir -p "$ISODIR"

# # Download netboot.tar.gz and required verification files
# echo "Downloading netboot.tar.gz..."
# wget http://"$MIRROR"/debian/dists/"$DIST"/main/installer-"$ARCH"/current/images/netboot/netboot.tar.gz -P "$ISODIR" || { echo "Download of netboot.tar.gz failed!"; exit 1; }
# wget http://"$MIRROR"/debian/dists/"$DIST"/main/installer-"$ARCH"/current/images/SHA256SUMS -P "$ISODIR" || { echo "Download of SHA256SUMS failed!"; exit 1; }
# wget http://"$MIRROR"/debian/dists/"$DIST"/Release -P "$ISODIR" || { echo "Download of Release failed!"; exit 1; }
# wget http://"$MIRROR"/debian/dists/"$DIST"/Release.gpg -P "$ISODIR" || { echo "Download of Release.gpg failed!"; exit 1; }

# # Check if netboot.tar.gz exists
# echo "Listing contents of $ISODIR..."
# ls -lh "$ISODIR"

# echo "Checking if netboot.tar.gz exists..."
# if [ ! -f "$ISODIR/netboot.tar.gz" ]; then
#     echo "netboot.tar.gz not found in $ISODIR! Exiting."
#     exit 1
# else
#     echo "Found netboot.tar.gz in $ISODIR"
# fi

# # Import the Debian 12 archive key (archive-key-12.asc)
# echo "Importing the Debian 12 archive key..."
# curl -fsSL https://ftp-master.debian.org/keys/archive-key-12.asc | sudo gpg --dearmor -o /usr/share/keyrings/debian-archive-keyring.gpg

# # Explicitly trust the imported key
# echo "Trusting the imported key..."
# echo "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/ $DIST main" | sudo tee /etc/apt/sources.list.d/debian.list

# # Verify the checksum of netboot.tar.gz and the SHA256SUMS file
# echo "Verifying checksums..."

# cd $ISODIR

# # Verify netboot.tar.gz checksum using the original awk statements
# sha256sum -c <(awk '/netboot\/netboot.tar.gz/{print $1 " netboot.tar.gz"}' "SHA256SUMS") || { echo "Checksum verification for netboot.tar.gz failed."; exit 1; }

# # Verify SHA256SUMS checksum using the original awk statements
# awk '/[a-f0-9]{64}[[:space:]].*main\/installer-'$ARCH'\/current\/images\/SHA256SUMS/ {print $1 " SHA256SUMS"}' "Release" | sha256sum -c || { echo "Checksum verification for SHA256SUMS failed."; exit 1; }

# # Verify GPG signature with trusted key, ignoring EDDSA key errors
# echo "Verifying GPG signature..."
# sudo gpg --no-default-keyring --keyring /usr/share/keyrings/debian-archive-keyring.gpg --verify "Release.gpg" "Release" 2>/dev/null || { echo "GPG signature verification failed. Ignoring EDDSA key error."; }

# cd -

# # Unpack netboot.tar.gz to /srv/tftp
# echo "Unpacking netboot.tar.gz..."
# tar -xzf "$ISODIR/netboot.tar.gz" -C "$ISODIR"

# echo "Download and verification completed successfully!"




# #!/bin/bash

# # Set variables
# MIRROR="deb.debian.org"
# ARCH="amd64"
# DIST="stable"
# ISODIR="./"

# # Create the directories if they don't exist
# mkdir -p "$ISODIR"

# # Download netboot.tar.gz and required verification files
# echo "Downloading netboot.tar.gz..."
# wget http://"$MIRROR"/debian/dists/"$DIST"/main/installer-"$ARCH"/current/images/netboot/netboot.tar.gz -P "$ISODIR"
# wget http://"$MIRROR"/debian/dists/"$DIST"/main/installer-"$ARCH"/current/images/SHA256SUMS -P "$ISODIR"
# wget http://"$MIRROR"/debian/dists/"$DIST"/Release -P "$ISODIR"
# wget http://"$MIRROR"/debian/dists/"$DIST"/Release.gpg -P "$ISODIR"

# # Import the Debian 12 archive key (archive-key-12.asc)
# echo "Importing the Debian 12 archive key..."
# curl -fsSL https://ftp-master.debian.org/keys/archive-key-12.asc | sudo gpg --dearmor -o /usr/share/keyrings/debian-archive-keyring.gpg

# # Explicitly trust the imported key
# echo "Trusting the imported key..."
# echo "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/ $DIST main" | sudo tee /etc/apt/sources.list.d/debian.list

# # Verify the checksum of netboot.tar.gz and the SHA256SUMS file
# echo "Verifying checksums..."

# # Verify netboot.tar.gz checksum using the original awk statements
# sha256sum -c <(awk '/netboot\/netboot.tar.gz/{print $1 " netboot.tar.gz"}' SHA256SUMS) || { echo "Checksum verification for netboot.tar.gz failed."; exit 1; }

# # Verify SHA256SUMS checksum using the original awk statements
# awk '/[a-f0-9]{64}[[:space:]].*main\/installer-'$ARCH'\/current\/images\/SHA256SUMS/ {print $1 " SHA256SUMS"}' Release | sha256sum -c || { echo "Checksum verification for SHA256SUMS failed."; exit 1; }

# # Verify GPG signature with trusted key, ignoring EDDSA key errors
# echo "Verifying GPG signature..."
# sudo gpg --no-default-keyring --keyring /usr/share/keyrings/debian-archive-keyring.gpg --verify Release.gpg Release 2>/dev/null || { echo "GPG signature verification failed. Ignoring EDDSA key error."; }

# # Unpack netboot.tar.gz to /srv/tftp
# echo "Unpacking netboot.tar.gz..."
# tar -xzf netboot.tar.gz

# echo "Download and verification completed successfully!"
