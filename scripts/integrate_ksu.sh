#!/bin/bash
# 把 SukiSU-Ultra 集成进 4.19.325 内核树（非 GKI，手动集成 + 4.19 兼容补丁）
set -e
cd kernel

rm -rf KernelSU
cp -r ../suki ./KernelSU
rm -rf drivers/kernelsu
ln -s ../KernelSU/kernel drivers/kernelsu

grep -q 'obj-$(CONFIG_KSU) += kernelsu/' drivers/Makefile || echo 'obj-$(CONFIG_KSU) += kernelsu/' >> drivers/Makefile
grep -q 'drivers/kernelsu/Kconfig' drivers/Kconfig || sed -i '237i source "drivers/kernelsu/Kconfig"' drivers/Kconfig

python3 - <<'PY'
import io, sys

def rd(p):
    return io.open(p, encoding='utf-8', errors='surrogateescape').read()

def wr(p, s):
    io.open(p, 'w', encoding='utf-8', errors='surrogateescape').write(s)

# 1) init.c: MODULE_IMPORT_NS 在 4.19 不存在
p = 'KernelSU/kernel/core/init.c'
s = rd(p)
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
    wr(p, s.replace(old, new))
    print('init.c patched')

# 2) file_wrapper.c: 5.x 才有的 f_op 成员，4.19 给空实现
p = 'KernelSU/kernel/infra/file_wrapper.c'
s = rd(p)
if '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)' not in s:
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
    wr(p, head + s + '\n#endif /* < 5.4 */\n')
    print('file_wrapper.c patched')

# 3) seccomp_cache.c: SECCOMP_ARCH_NATIVE_NR 是 5.10+ 才有的
p = 'KernelSU/kernel/infra/seccomp_cache.c'
s = rd(p)
if '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)' not in s:
    head = '''#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
struct seccomp_filter;
void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
}
void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
}
#else
'''
    wr(p, head + s + '\n#endif /* < 5.10 */\n')
    print('seccomp_cache.c patched')

# 4) su_mount_ns.c: path_mount 是 5.2+ 的内部 API
p = 'KernelSU/kernel/infra/su_mount_ns.c'
s = rd(p)
if '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)' not in s:
    head = '''#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
void setup_mount_ns(int32_t ns_mode)
{
    (void)ns_mode;
}
#else
'''
    wr(p, head + s + '\n#endif /* < 5.4 */\n')
    print('su_mount_ns.c patched')

# 5) pkg_observer.c: fsnotify handle_inode_event 是 5.9+，4.19 用 handle_event
p = 'KernelSU/kernel/manager/pkg_observer.c'
s = rd(p)
old = '''static int ksu_handle_inode_event(struct fsnotify_mark *mark, u32 mask, struct inode *inode, struct inode *dir,
                                  const struct qstr *file_name, u32 cookie)
{
    if (!file_name)
        return 0;
    if (mask & FS_ISDIR)
        return 0;
    if (file_name->len == 13 && !memcmp(file_name->name, "packages.list", 13)) {
        pr_info("packages.list detected: %d\\n", mask);
        ksu_defer_track_throne();
    }
    return 0;
}'''
new = '''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static int ksu_handle_inode_event(struct fsnotify_group *group, struct inode *inode,
                                  u32 mask, const void *data, int data_type,
                                  const unsigned char *file_name, u32 cookie,
                                  struct fsnotify_iter_info *iter_info)
{
    if (!file_name)
        return 0;
    if (mask & FS_ISDIR)
        return 0;
    if (strlen(file_name) == 13 && !memcmp(file_name, "packages.list", 13)) {
        pr_info("packages.list detected: %d\\n", mask);
        ksu_defer_track_throne();
    }
    return 0;
}
#define KSU_FSNOTIFY_HANDLER .handle_event = ksu_handle_inode_event
#else
static int ksu_handle_inode_event(struct fsnotify_mark *mark, u32 mask, struct inode *inode, struct inode *dir,
                                  const struct qstr *file_name, u32 cookie)
{
    if (!file_name)
        return 0;
    if (mask & FS_ISDIR)
        return 0;
    if (file_name->len == 13 && !memcmp(file_name->name, "packages.list", 13)) {
        pr_info("packages.list detected: %d\\n", mask);
        ksu_defer_track_throne();
    }
    return 0;
}
#define KSU_FSNOTIFY_HANDLER .handle_inode_event = ksu_handle_inode_event
#endif'''
if old in s:
    s = s.replace(old, new)
    s = s.replace('    .handle_inode_event = ksu_handle_inode_event,\n', '    KSU_FSNOTIFY_HANDLER,\n')
    wr(p, s)
    print('pkg_observer.c patched')

# 6) allowlist.c: TWA_RESUME 与 put_task_struct
p = 'KernelSU/kernel/policy/allowlist.c'
s = rd(p)
if 'KSU_TWA_RESUME_COMPAT' not in s:
    s = s.replace('#include "policy/allowlist.h"',
                  '#include "policy/allowlist.h"\n\n#ifndef TWA_RESUME /* KSU_TWA_RESUME_COMPAT */\n#define TWA_RESUME true\n#endif\n#include <linux/sched/task.h>', 1)
    wr(p, s)
    print('allowlist.c patched')

# 7) app_profile.c: seccomp.filter_count 是 5.x
p = 'KernelSU/kernel/policy/app_profile.c'
s = rd(p)
old = '    atomic_set(&current->seccomp.filter_count, 0);\n'
new = '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)\n    atomic_set(&current->seccomp.filter_count, 0);\n#endif\n'
if old in s:
    wr(p, s.replace(old, new, 1))
    print('app_profile.c patched')

# 8) cpu_spoof.c: clocksource.vdso_clock_mode 是 5.5+
p = 'KernelSU/kernel/extension/cpu_spoof.c'
s = rd(p)
old = '''                        (*curr_cs_ptr)->vdso_clock_mode =
                            VDSO_CLOCKMODE_ARCHTIMER;'''
new = '''#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
                        (*curr_cs_ptr)->vdso_clock_mode =
                            VDSO_CLOCKMODE_ARCHTIMER;
#endif'''
if old in s and 'KERNEL_VERSION(5, 5, 0)' not in s:
    wr(p, s.replace(old, new, 1))
    print('cpu_spoof.c patched')

# 9) selinux: 安装 4.19 专用完整实现（就地适配 policydb/sidtab 结构，支持策略注入）
import shutil
shutil.copy('../patches/sepolicy_419.h', 'KernelSU/kernel/selinux/sepolicy.h')
shutil.copy('../patches/sepolicy_419.c', 'KernelSU/kernel/selinux/sepolicy.c')
shutil.copy('../patches/rules_419.c', 'KernelSU/kernel/selinux/rules.c')
print('selinux 4.19 full implementation installed')

# 11) feature/selinux_hide.c: 4.19 无 selinux status_page/status_lock
p = 'KernelSU/kernel/feature/selinux_hide.c'
s = rd(p)
if '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)' not in s:
    head = '''#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
void ksu_selinux_hide_init(void)
{
}
void ksu_selinux_hide_exit(void)
{
}
#else
'''
    wr(p, head + s + '\n#endif\n')
    print('selinux_hide.c patched')

# 12) supercall: tasklist_lock / task_pgrp / init_task / TWA_RESUME
extra = '''#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/init_task.h>
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
'''
for p in ['KernelSU/kernel/supercall/dispatch.c', 'KernelSU/kernel/supercall/supercall.c']:
    s = rd(p)
    if 'linux/sched/signal.h' not in s:
        wr(p, extra + s)
        print(p + ' patched')

# 13) sulog/event.c: linux/minmax.h 在 4.19 不存在
p = 'KernelSU/kernel/sulog/event.c'
s = rd(p)
if '#include <linux/minmax.h>' in s:
    wr(p, s.replace('#include <linux/minmax.h>', '#include <linux/kernel.h>'))
    print('sulog/event.c patched')
PY

python3 - <<'PY2'
import io
def rd(p):
    return io.open(p, encoding='utf-8', errors='surrogateescape').read()
def wr(p, s):
    io.open(p, 'w', encoding='utf-8', errors='surrogateescape').write(s)

# 14) selinux_hide: 4.19 分支补齐全部钩子函数（重写 #if <5.0 .. #else 之间的内容）
import re
p = 'KernelSU/kernel/feature/selinux_hide.c'
s = rd(p)
stub = '''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
void ksu_selinux_hide_init(void)
{
}
void ksu_selinux_hide_exit(void)
{
}
void ksu_selinux_hide_drop_backup_if_unused(void)
{
}
void ksu_selinux_hide_handle_second_stage(void)
{
}
void ksu_selinux_hide_handle_post_fs_data(void)
{
}
'''
if 'ksu_selinux_hide_handle_post_fs_data(void)\n{\n}\n#else' not in s:
    s2 = re.sub(r'#if LINUX_VERSION_CODE < KERNEL_VERSION\(5, 0, 0\).*?\n#else\n',
                stub + '#else\n', s, count=1, flags=re.S)
    wr(p, s2)
    print('selinux_hide hooks ok' if s2 != s else 'selinux_hide hooks FAILED')

# 15) kernel_umount: 4.19 无 path_umount
p = 'KernelSU/kernel/feature/kernel_umount.c'
s = rd(p)
if 'KERNEL_VERSION(5, 9, 0)' not in s:
    s = s.replace(
        'static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)\n{\n    int err = path_umount(path, flags);',
        'static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)\n{\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)\n    (void)mnt; (void)path; (void)flags;\n    return;\n#else\n    int err = path_umount(path, flags);', 1)
    s = s.replace(
        '    if (err) {\n        pr_info("umount %s failed: %d\\n", mnt, err);\n    }\n}',
        '    if (err) {\n        pr_info("umount %s failed: %d\\n", mnt, err);\n    }\n#endif\n}', 1)
    wr(p, s)
    print('kernel_umount ok')

# 16) app_profile: 4.19 无 seccomp_filter_release
p = 'KernelSU/kernel/policy/app_profile.c'
s = rd(p)
if '>= KERNEL_VERSION(5, 9, 0)\n    seccomp_filter_release(fake);' not in s:
    s = s.replace(
        '    seccomp_filter_release(fake);',
        '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)\n    seccomp_filter_release(fake);\n#endif', 1)
    wr(p, s)
    print('app_profile release ok')
# 17) 保持标准 ksu 域与 /data/adb/ksud 路径（域和规则由内核 apply_kernelsu_rules 注入）
#     只放开 allow_shell，便于 shell 侧调试
p = 'KernelSU/kernel/core/init.c'
s = rd(p)
if 'bool allow_shell = false;' in s:
    wr(p, s.replace('bool allow_shell = false;', 'bool allow_shell = true;', 1))
    print('allow_shell -> true')
# 18) 4.19: the execve hook runs inside a kprobe pre_handler (preemption off).
#     All policy work allocates with GFP_KERNEL, so it must run from a workqueue.
p = 'KernelSU/kernel/selinux/selinux.h'
s = rd(p)
if '#define KERNEL_SU_DOMAIN "shell"' in s:
    wr(p, s.replace('#define KERNEL_SU_DOMAIN "shell"', '#define KERNEL_SU_DOMAIN "ksu"', 1))
    print('KERNEL_SU_DOMAIN -> ksu')

p = 'KernelSU/kernel/runtime/ksud_integration.c'
s = rd(p)
old = "            apply_kernelsu_rules();\n            cache_sid();\n            setup_ksu_cred();\n"
new = "            ksu_schedule_policy_init();\n"
if old in s:
    wr(p, s.replace(old, new, 1))
    print('ksud_integration -> deferred policy init')
else:
    print('ksud_integration pattern NOT FOUND')
PY2

echo "集成完成"
