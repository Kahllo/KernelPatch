/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("safe");
KPM_DESCRIPTION("Block access to /proc/self/status to evade debugger detection");

// Simple string prefix check to avoid strstr entirely
static int is_proc_self_status(const char *path) {
    const char *target = "/proc/self/status";
    int i = 0;
    while (path[i] && target[i]) {
        if (path[i] != target[i]) return 0;
        i++;
    }
    return target[i] == '\0';
}

void before_openat(hook_fargs4_t *args, void *udata) {
    const char *filename = (const char *)syscall_argn(args, 1);
    if (filename && is_proc_self_status(filename)) {
        pr_info("[anti-debug] blocked access to /proc/self/status\n");
        args->ret = -1;
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[anti-debug] init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) {
        pr_err("[anti-debug] hook failed\n");
        return -1;
    }
    pr_info("[anti-debug] hook success\n");
    return 0;
}

static long anti_debug_exit(void *__user reserved) {
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] exit\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_EXIT(anti_debug_exit);
