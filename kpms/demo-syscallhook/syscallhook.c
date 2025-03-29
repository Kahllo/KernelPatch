/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Bypass TracerPid and file-based debugger detection (safe)");

// Local strstr (safe)
static char *local_strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; ++haystack) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) {
            ++h; ++n;
        }
        if (!*n) return (char *)haystack;
    }
    return NULL;
}

// Local safe path filter
static int is_debug_path(const char *path) {
    return path && (
        local_strstr(path, "/proc/self/status") ||
        local_strstr(path, "/proc/self/maps") ||
        local_strstr(path, "/proc/self/mem") ||
        local_strstr(path, "/proc/self/pagemap")
    );
}

// Hook openat: block suspicious debugger file paths
void before_openat(hook_fargs4_t *args, void *udata) {
    const char *fname = (const char *)syscall_argn(args, 1);
    if (is_debug_path(fname)) {
        pr_info("[anti-debug] blocked openat: %s\n", fname);
        args->ret = -ENOENT;
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[anti-debug] init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) pr_err("[anti-debug] hook error: %d\n", err);
    else pr_info("[anti-debug] hook installed\n");
    return 0;
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen) {
    pr_info("[anti-debug] ctl: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved) {
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] unhooked\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
