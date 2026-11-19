#!/bin/bash
# clang-14 + binutils-aarch64 编译 Image.gz
set -e
cd kernel
export ARCH=arm64
export SUBARCH=arm64

make O=out -j"$(nproc)" \
  CC=clang-14 \
  CLANG_TRIPLE=aarch64-linux-gnu- \
  CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
  LD=aarch64-linux-gnu-ld \
  Image.gz

ls -l out/arch/arm64/boot/Image.gz
sha256sum out/arch/arm64/boot/Image.gz
