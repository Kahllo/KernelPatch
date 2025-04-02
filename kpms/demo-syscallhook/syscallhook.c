/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/kallsyms.h>
#include <kphooks.h>  // Required for hook_function, unhook_function

KPM_NAME("kpm-ptrace-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kahllo");
KPM_DESCRIPTION("Bypass TracerPid by hooking ptrace_parent to return NULL");

// Define original ptrace_parent pointer
typedef struct task_struct *(*ptrace_parent_t)(struct task_struct *);
static ptrace_parent_t real_ptrace_parent = NULL;

// Hook function: always pretend no tracer is attached
static struct task_struct *fake_ptrace_parent(struct task_struct *child) {
    if (child && child->comm) {
        pr_info("[kpm-ptrace-bypass] ptrace_parent called for task\n");
    }
    return NULL;
}

static long ptrace_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-ptrace-bypass] Initializing module...\n");

    // Resolve ptrace_parent symbol
    real_ptrace_parent = (ptrace_parent_t)kallsyms_lookup_name("ptrace_parent");
    if (!real_ptrace_parent) {
        pr_err("[kpm-ptrace-bypass] Failed to find ptrace_parent symbol\n");
        return -1;
    }

    // Hook ptrace_parent
    int err = hook_function((void *)real_ptrace_parent, (void *)fake_ptrace_parent, (void **)&real_ptrace_parent);
    if (err != 0) {
        pr_err("[kpm-ptrace-bypass] Failed to hook ptrace_parent: %d\n", err);
        return -1;
    }

    pr_info("[kpm-ptrace-bypass] ptrace_parent successfully hooked\n");
    return 0;
}

static long ptrace_bypass_exit(void *__user reserved)
{
    if (real_ptrace_parent) {
        unhook_function((void *)real_ptrace_parent);
        pr_info("[kpm-ptrace-bypass] ptrace_parent unhooked\n");
    }
    return 0;
}

KPM_INIT(ptrace_bypass_init);
KPM_EXIT(ptrace_bypass_exit);
