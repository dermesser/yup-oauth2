#!/usr/bin/env bash

set -o verbose
set -o errexit
set -o pipefail

PROGRAM_NAME="${1}"

echo "Coverage testing of ${PROGRAM_NAME}"

for file in target/debug/${PROGRAM_NAME}-*; do
    [ -x "${file}" ] || continue
    mkdir -p "target/cov/$(basename ${file})";
    kcov --exclude-pattern='/.cargo,/usr/lib' --verify "target/cov/$(basename ${file})" "${file}";
done
