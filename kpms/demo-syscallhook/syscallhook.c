/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("0.1.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Safe anti-debug syscall hook test");

// openat hook: no user pointer dereferencing
void before_openat(hook_fargs4_t *args, void *udata)
{
    pr_info("[anti-debug] openat syscall intercepted\n");
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] init: installing hook\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err)
        pr_err("[anti-debug] hook install failed: %d\n", err);
    else
        pr_info("[anti-debug] hook installed successfully\n");
    return 0;
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[anti-debug] control command: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    pr_info("[anti-debug] hook removed, exiting\n");
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
