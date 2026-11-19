#!/bin/bash
# 把 SukiSU-Ultra 集成进 4.19.325 内核树（非 GKI，手动集成）
set -e
cd kernel

rm -rf KernelSU
cp -r ../suki ./KernelSU
rm -rf drivers/kernelsu
ln -s ../KernelSU/kernel drivers/kernelsu

grep -q 'obj-$(CONFIG_KSU) += kernelsu/' drivers/Makefile || echo 'obj-$(CONFIG_KSU) += kernelsu/' >> drivers/Makefile
grep -q 'drivers/kernelsu/Kconfig' drivers/Kconfig || sed -i '237i source "drivers/kernelsu/Kconfig"' drivers/Kconfig

python3 - <<'PY'
# 1) init.c: MODULE_IMPORT_NS 在 4.19 不存在
p = 'KernelSU/kernel/core/init.c'
s = open(p).read()
old = '''#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif'''
new = '''#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif'''
if old in s:
    open(p, 'w').write(s.replace(old, new))
    print('init.c patched')

# 2) file_wrapper.c: 5.x 才有的 f_op 成员，4.19 给空实现
p = 'KernelSU/kernel/infra/file_wrapper.c'
s = open(p).read()
guard = '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)'
if guard not in s:
    head = '''#include <linux/errno.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
int ksu_install_file_wrapper(int fd)
{
    return -95; /* -EOPNOTSUPP */
}
void ksu_file_wrapper_init(void)
{
}
#else
'''
    open(p, 'w').write(head + s + '\n#endif /* < 5.4 */\n')
    print('file_wrapper.c patched')
PY

echo "集成完成"
