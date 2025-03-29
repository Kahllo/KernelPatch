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
KPM_DESCRIPTION("Safe anti-debug openat hook - block /proc/self/status only");

// Simple prefix match (no strstr)
static int starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

// openat hook: block /proc/self/status
void before_openat(hook_fargs4_t *args, void *udata) {
    const char *filename = (const char *)syscall_argn(args, 1);
    if (filename && starts_with(filename, "/proc/self/status")) {
        pr_info("[anti-debug] blocked openat: %s\n", filename);
        args->ret = -1;
    } else {
        pr_info("[anti-debug] openat allowed\n");
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[anti-debug] init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) {
        pr_err("[anti-debug] hook failed\n");
        return -1;
    }
    pr_info("[anti-debug] hook installed\n");
    return 0;
}

static long anti_debug_exit(void *__user reserved) {
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] exit\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_EXIT(anti_debug_exit);
