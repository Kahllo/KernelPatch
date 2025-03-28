/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Minimal safe syscall hook test");

// Minimal and safe strstr replacement
static char *local_strstr(const char *haystack, const char *needle)
{
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            ++h;
            ++n;
        }
        if (!*n) return (char *)haystack;
    }
    return NULL;
}

// Simple openat hook
void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char *name = (char *)filename;

    // Dangerous direct check but safe if only used for log testing
    if (name && (
        local_strstr(name, "status") ||
        local_strstr(name, "maps"))) {
        pr_info("[anti-debug] openat requested: %s\n", name);
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] Minimal test init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) {
        pr_err("[anti-debug] Hook failed\n");
    } else {
        pr_info("[anti-debug] Hook success\n");
    }
    return 0;
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[anti-debug] control received\n");
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
