#!/bin/bash
# 生成 bengal-perf + j606f 配置，并打开 KSU 所需选项
set -e
cd kernel
export ARCH=arm64
export SUBARCH=arm64

rm -rf out
mkdir -p out

make O=out vendor/bengal-perf_defconfig

if [ -f arch/arm64/configs/vendor/ext_config/j606f.config ]; then
  ARCH=arm64 scripts/kconfig/merge_config.sh -m -O out out/.config arch/arm64/configs/vendor/ext_config/j606f.config || true
  make O=out olddefconfig
fi

./scripts/config --file out/.config \
  -e KPROBES -e KALLSYMS_ALL -e KALLSYMS -e EXT4_FS -e KSU -d KSU_DEBUG \
  -d MODVERSIONS -e MODULES

make O=out olddefconfig

grep -E "^CONFIG_(KSU|KPROBES|KALLSYMS_ALL|EXT4_FS|MODULES|MODVERSIONS)=" out/.config || true
echo "配置完成"
