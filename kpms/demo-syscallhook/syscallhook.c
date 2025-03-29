/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("0.3.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Minimal and safe anti-debug module");

/* Safe internal strstr implementation */
static char *local_strstr(const char *haystack, const char *needle)
{
    if (!*needle) return (char *)haystack;
    for (; *haystack; ++haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            ++h;
            ++n;
        }
        if (!*n) return (char *)haystack;
    }
    return 0;
}

/* Check if the path matches known debugger access files */
static int is_debug_path(const char *path) {
    if (!path) return 0;
    if (local_strstr(path, "/proc/self/status")) return 1;
    if (local_strstr(path, "/proc/self/maps")) return 1;
    if (local_strstr(path, "/proc/self/mem")) return 1;
    if (local_strstr(path, "/proc/self/pagemap")) return 1;
    return 0;
}

/* openat syscall hook */
void before_openat(hook_fargs4_t *args, void *udata)
{
    const char *filename = (const char *)syscall_argn(args, 1);
    if (is_debug_path(filename)) {
        pr_info("[anti-debug] blocked openat: %s\n", filename);
        args->ret = -ENOENT;
    }
}

/* KPM lifecycle hooks */
static long anti_debug_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err)
        pr_err("[anti-debug] hook failed: %d\n", err);
    else
        pr_info("[anti-debug] hook installed\n");
    return 0;
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[anti-debug] control: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] unhooked\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
