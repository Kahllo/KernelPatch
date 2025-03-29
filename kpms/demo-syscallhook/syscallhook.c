/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_minimal");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Minimal safe anti-debug hook: block /proc/self/status");

// Simple string comparison (no external symbol usage)
static int is_proc_self_status(const char *path) {
    const char *target = "/proc/self/status";
    int i = 0;
    while (path[i] && target[i]) {
        if (path[i] != target[i]) return 0;
        i++;
    }
    return (path[i] == '\0' && target[i] == '\0');
}

void before_openat(hook_fargs4_t *args, void *udata) {
    const char *filename = (const char *)syscall_argn(args, 1);
    if (!filename) return;

    // Just check if it's "/proc/self/status"
    if (is_proc_self_status(filename)) {
        pr_info("[anti-debug] blocked openat on /proc/self/status\n");
        args->ret = -ENOENT;
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[anti-debug] init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);

    if (err)
        pr_err("[anti-debug] hook failed\n");
    else
        pr_info("[anti-debug] hook installed\n");

    return 0;
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen) {
    pr_info("[anti-debug] control command: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved) {
    pr_info("[anti-debug] exit\n");
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
