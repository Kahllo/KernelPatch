/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("anti_debug_status_blocker");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Block /proc/self/status and /proc/self/task/*/status");

#define PROC_SELF_STATUS "/proc/self/status"
#define PROC_SELF_TASK "/proc/self/task/"

void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256] = {0};

    if (compat_strncpy_from_user(buf, filename, sizeof(buf)) <= 0)
        return;

    // Exact or prefix match
    if (!__builtin_strcmp(buf, "/proc/self/status") ||
        (__builtin_strncmp(buf, "/proc/self/task/", 17) == 0 &&
         __builtin_strstr(buf, "/status") != 0)) {

        pr_info("[anti-debug] blocked openat: %s\n", buf);
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

static long init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) pr_err("[anti-debug] hook failed: %d\n", err);
    return 0;
}

static long exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] exit\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);
