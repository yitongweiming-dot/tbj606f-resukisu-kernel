#!/bin/bash
# 生成 bengal-perf + j606f 配置，并打开 KSU 所需选项
# 这里的 make 变量必须和 build_kernel.sh 完全一致，否则编译时会重跑 syncconfig 并失败
set -e
cd kernel
export ARCH=arm64
export SUBARCH=arm64

MKARGS="O=out ARCH=arm64 CC=clang-14 CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi- LD=aarch64-linux-gnu-ld"

rm -rf out
mkdir -p out

make $MKARGS vendor/bengal-perf_defconfig

if [ -f arch/arm64/configs/vendor/ext_config/j606f.config ]; then
  ARCH=arm64 scripts/kconfig/merge_config.sh -m -O out out/.config arch/arm64/configs/vendor/ext_config/j606f.config || true
  make $MKARGS olddefconfig
fi

./scripts/config --file out/.config \
  -e KPROBES -e KALLSYMS_ALL -e KALLSYMS -e EXT4_FS -e KSU -d KSU_DEBUG \
  -e MODVERSIONS -e MODULES -d DEBUG_INFO -d DEBUG_INFO_DWARF4

make $MKARGS olddefconfig

grep -E "^CONFIG_(KSU|KPROBES|KALLSYMS_ALL|EXT4_FS|MODULES|MODVERSIONS|DEBUG_INFO)=" out/.config || true
echo "配置完成"
