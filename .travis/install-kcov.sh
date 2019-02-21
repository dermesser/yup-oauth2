#!/usr/bin/env bash

set -o verbose
set -o errexit
set -o pipefail

KCOV_VERSION="${1}"
KCOV_SHA256_HASH="${2}"

curl -L --output "kcov.tar.gz" "https://github.com/SimonKagstrom/kcov/archive/${KCOV_VERSION}.tar.gz"
sha256sum "kcov.tar.gz"
echo "${KCOV_SHA256_HASH}  kcov.tar.gz" | sha256sum -c

mkdir kcov-src
mkdir kcov

cd kcov-src
tar -xf ../kcov.tar.gz --strip-components=1
rm ../kcov.tar.gz

mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ..
make -j 2
make install DESTDIR=../../kcov
cd ../../
rm -r kcov-src

echo "kcov should not be available via 'kcov/usr/bin/kcov'"
