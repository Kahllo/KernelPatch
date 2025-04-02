/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("kpm-tracerpid-bypass");
KPM_VERSION("1.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kahllo");
KPM_DESCRIPTION("Bypass TracerPid by hooking task_state()");

enum hook_type hook_type = NONE;

// Pointer to original task_state function
static void (*real_task_state)(void *m, void *ns, void *pid, struct task_struct *task) = NULL;

// Our patched version – suppress TracerPid line
static void patched_task_state(void *m, void *ns, void *pid, struct task_struct *task)
{
    // do nothing, skip writing TracerPid
    return;
}

static long tracerpid_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-tracerpid-bypass] init\n");

    // Get address of task_state symbol
    real_task_state = (void *)kallsyms_lookup_name("task_state");
    if (!real_task_state) {
        pr_err("[kpm-tracerpid-bypass] task_state not found\n");
        return -1;
    }

    // Use KPM’s generic function patching
    int err = inline_hook_function_ptr((void *)real_task_state, (void *)patched_task_state);
    if (err) {
        pr_err("[kpm-tracerpid-bypass] Failed to hook task_state: %d\n", err);
        return -1;
    }

    hook_type = INLINE_CHAIN;
    pr_info("[kpm-tracerpid-bypass] Hook installed\n");
    return 0;
}

static long tracerpid_bypass_exit(void *__user reserved)
{
    if (real_task_state && hook_type == INLINE_CHAIN) {
        inline_unhook_function_ptr((void *)real_task_state);
        pr_info("[kpm-tracerpid-bypass] Unhooked task_state\n");
    }
    return 0;
}

KPM_INIT(tracerpid_bypass_init);
KPM_EXIT(tracerpid_bypass_exit);
