/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("kpm-tracerpid-bypass");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kahllo");
KPM_DESCRIPTION("Bypass TracerPid by hooking task_state");

enum hook_type hook_type = NONE;

// Define function pointer
static void (*real_task_state)(void *m, void *ns, void *pid, struct task_struct *p) = NULL;

static void fake_task_state(void *m, void *ns, void *pid, struct task_struct *p)
{
    // Call original, but patch TracerPid line
    if (!p) return;

    // Minimal printf replacement to hide TracerPid
    // Normally task_state uses seq_printf, but we don't depend on seq_file
    // So we avoid showing TracerPid at all (kernel fallback is OK)
    return; // noop to suppress TracerPid entirely
}

static long tracerpid_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-tracerpid-bypass] init\n");

    real_task_state = (void *)kallsyms_lookup_name("task_state");
    if (!real_task_state) {
        pr_err("[kpm-tracerpid-bypass] Failed to find task_state\n");
        return -1;
    }

    hook_err_t err = inline_hook_function((void *)real_task_state, (void *)fake_task_state);
    if (err) {
        pr_err("[kpm-tracerpid-bypass] Failed to hook task_state: %d\n", err);
        return -1;
    }

    pr_info("[kpm-tracerpid-bypass] Hooked task_state\n");
    hook_type = INLINE_CHAIN;
    return 0;
}

static long tracerpid_bypass_exit(void *__user reserved)
{
    if (real_task_state && hook_type == INLINE_CHAIN) {
        inline_unhook_function((void *)real_task_state);
        pr_info("[kpm-tracerpid-bypass] Unhooked task_state\n");
    }
    return 0;
}

KPM_INIT(tracerpid_bypass_init);
KPM_EXIT(tracerpid_bypass_exit);
