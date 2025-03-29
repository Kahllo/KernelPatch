/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>

KPM_NAME("anti_debug_proc_status");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Blocks access to /proc/self/status to bypass TracerPid detection");

void before_openat(hook_fargs4_t *args, void *udata)
{
    const char *path = (const char *)syscall_argn(args, 1);

    // Only check the first few characters to match "/proc/self/status"
    if (path &&
        path[0] == '/' &&
        path[1] == 'p' &&
        path[2] == 'r' &&
        path[3] == 'o' &&
        path[4] == 'c' &&
        path[5] == '/' &&
        path[6] == 's' &&
        path[7] == 'e' &&
        path[8] == 'l' &&
        path[9] == 'f' &&
        path[10] == '/' &&
        path[11] == 's' &&
        path[12] == 't' &&
        path[13] == 'a' &&
        path[14] == 't' &&
        path[15] == 'u' &&
        path[16] == 's' &&
        path[17] == '\0') {

        pr_info("[anti-debug] blocked /proc/self/status\n");
        args->ret = -ENOENT;
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] init\n");
    return inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[anti-debug] ctl: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] exit\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
