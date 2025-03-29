/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("safe");
KPM_DESCRIPTION("Minimal Anti-Debug openat hook");

// Simple local strstr replacement (safe for KPM)
static int contains_pattern(const char *str, const char *pattern) {
    if (!str || !pattern) return 0;
    while (*str) {
        const char *a = str;
        const char *b = pattern;
        while (*a && *b && *a == *b) {
            a++; b++;
        }
        if (!*b) return 1;
        str++;
    }
    return 0;
}

// This list contains the patterns we want to block
static int is_suspicious_path(const char *path) {
    return contains_pattern(path, "/proc/self/status") ||
           contains_pattern(path, "/proc/self/maps")   ||
           contains_pattern(path, "/proc/self/mem")    ||
           contains_pattern(path, "/proc/self/pagemap");
}

// openat hook implementation
void before_openat(hook_fargs4_t *args, void *udata) {
    const char *filename = (const char *)syscall_argn(args, 1);
    if (filename && is_suspicious_path(filename)) {
        pr_info("[anti-debug] blocked openat to: %s\n", filename);
        args->ret = -1;
    } else {
        pr_info("[anti-debug] openat syscall intercepted\n");
    }
}

// Module initialization
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

// Module cleanup
static long anti_debug_exit(void *__user reserved) {
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] exit\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_EXIT(anti_debug_exit);
