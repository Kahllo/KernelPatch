/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("kpm-tracerpid-bypass");
KPM_VERSION("1.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kahllo");
KPM_DESCRIPTION("Bypass TracerPid by hooking task_state()");

enum hook_type hook_type = NONE;

static void (*real_task_state)(void *m, void *ns, void *pid, struct task_struct *task) = NULL;

// Replacement for task_state – skip printing TracerPid
static void fake_task_state(void *m, void *ns, void *pid, struct task_struct *task)
{
    // We do not write the TracerPid line here – this hides debugger presence
    return;
}

static long tracerpid_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-tracerpid-bypass] init\n");

    real_task_state = (void *)kallsyms_lookup_name("task_state");
    if (!real_task_state) {
        pr_err("[kpm-tracerpid-bypass] task_state not found\n");
        return -1;
    }

    hook_err_t err = inline_hook_function((void *)real_task_state, (void *)fake_task_state);
    if (err) {
        pr_err("[kpm-tracerpid-bypass] hook failed: %d\n", err);
        return -1;
    }

    pr_info("[kpm-tracerpid-bypass] hook installed\n");
    hook_type = INLINE_CHAIN;
    return 0;
}

static long tracerpid_bypass_exit(void *__user reserved)
{
    if (hook_type == INLINE_CHAIN && real_task_state) {
        inline_unhook_function((void *)real_task_state);
        pr_info("[kpm-tracerpid-bypass] unhooked\n");
    }
    return 0;
}

KPM_INIT(tracerpid_bypass_init);
KPM_EXIT(tracerpid_bypass_exit);
