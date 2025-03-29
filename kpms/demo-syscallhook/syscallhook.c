/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>

KPM_NAME("openat_status_blocker");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Hook openat and block /proc/self/status");

void before_openat(hook_fargs4_t *args, void *udata) {
    const char *path = (const char *)syscall_argn(args, 1);
    if (!path) return;

    // Manual comparison to "/proc/self/status" (16 chars + null terminator)
    const char match[] = "/proc/self/status";
    int matched = 1;
    for (int i = 0; i < sizeof(match); i++) {
        if (path[i] != match[i]) {
            matched = 0;
            break;
        }
    }

    if (matched) {
        pr_info("[anti-debug] blocked openat on /proc/self/status\n");
        args->ret = -1;  // Return error
    }
}

static long mod_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[anti-debug] module init\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err)
        pr_err("[anti-debug] failed to hook openat\n");
    else
        pr_info("[anti-debug] hooked openat successfully\n");
    return 0;
}

static long mod_exit(void *__user reserved) {
    pr_info("[anti-debug] module exit\n");
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    return 0;
}

KPM_INIT(mod_init);
KPM_EXIT(mod_exit);
