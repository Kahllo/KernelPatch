/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <syscall.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("kpm-tracerpid-bypass");
KPM_VERSION("1.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kahllo");
KPM_DESCRIPTION("Bypass TracerPid by hooking task_state");

enum hook_type hook_type = NONE;

static void *task_state_sym = NULL;

void before_task_state(hook_fargs4_t *args, void *udata)
{
    // Suppress printing TracerPid by skipping the original function
    args->skip_origin = 1;

    // Optional: log that we skipped TracerPid display
    pr_info("[kpm-tracerpid-bypass] Skipped task_state to hide TracerPid\n");
}

void after_task_state(hook_fargs4_t *args, void *udata)
{
    // We don't do anything after
}

static long tracerpid_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-tracerpid-bypass] init\n");

    task_state_sym = (void *)kallsyms_lookup_name("task_state");
    if (!task_state_sym) {
        pr_err("[kpm-tracerpid-bypass] Failed to resolve task_state\n");
        return -1;
    }

    hook_err_t err = hook_wrap2(task_state_sym, before_task_state, after_task_state, 0);
    if (err) {
        pr_err("[kpm-tracerpid-bypass] Hook failed: %d\n", err);
        return -1;
    }

    pr_info("[kpm-tracerpid-bypass] Hook installed\n");
    hook_type = INLINE_CHAIN;
    return 0;
}

static long tracerpid_bypass_exit(void *__user reserved)
{
    if (hook_type == INLINE_CHAIN && task_state_sym) {
        unhook_wrap2(task_state_sym, before_task_state, after_task_state);
        pr_info("[kpm-tracerpid-bypass] Unhooked task_state\n");
    }

    return 0;
}

KPM_INIT(tracerpid_bypass_init);
KPM_EXIT(tracerpid_bypass_exit);
