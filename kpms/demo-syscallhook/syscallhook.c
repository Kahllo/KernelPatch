/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("kpm-debugger-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Block /proc/self/status from being opened via openat");

#define PROC_SELF_STATUS "/proc/self/status"

enum hook_type hook_type = NONE;

void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256];
    for (int i = 0; i < sizeof(buf); ++i) buf[i] = 0;

    // Safe string copy from userspace
    if (compat_strncpy_from_user(buf, filename, sizeof(buf)) <= 0)
        return;

    // Block exact match to /proc/self/status
    if (!__builtin_strcmp(buf, PROC_SELF_STATUS)) {
        pr_info("[kpm-debugger-bypass] Blocked access to %s\n", buf);
        args->ret = -ENOENT;
        args->skip_origin = 1; // Only use this if skip_origin is supported by your KPM version
    }
}

static long debugger_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-debugger-bypass] init\n");

    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) {
        pr_err("[kpm-debugger-bypass] Failed to hook openat: %d\n", err);
    } else {
        pr_info("[kpm-debugger-bypass] Hook installed\n");
        hook_type = INLINE_CHAIN;
    }

    return 0;
}

static long debugger_bypass_exit(void *__user reserved)
{
    pr_info("[kpm-debugger-bypass] exit\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat, 0);
        pr_info("[kpm-debugger-bypass] Unhooked openat\n");
    }

    return 0;
}

KPM_INIT(debugger_bypass_init);
KPM_EXIT(debugger_bypass_exit);
