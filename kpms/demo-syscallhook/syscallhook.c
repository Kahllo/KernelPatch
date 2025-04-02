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

static void *task_state_sym = NULL;
static enum hook_type hook_type = NONE;

// hook_wrap2 requires this prototype
void before_task_state(hook_fargs4_t *fargs, void *udata)
{
    struct task_struct *p = (struct task_struct *)fargs->args[3];

    if (!p) return;

    // Suppress the output of TracerPid by skipping the function call
    pr_info("[kpm-tracerpid-bypass] Hiding TracerPid for: %s\n", p->comm);
    fargs->skip_origin = 1;
}

void after_task_state(hook_fargs4_t *fargs, void *udata) {
    // No-op
}

static long tracerpid_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[kpm-tracerpid-bypass] init\n");

    task_state_sym = (void *)kallsyms_lookup_name("task_state");
    if (!task_state_sym) {
        pr_err("[kpm-tracerpid-bypass] Failed to find task_state symbol\n");
        return -1;
    }

    hook_err_t err = hook_wrap2(task_state_sym, before_task_state, after_task_state, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[kpm-tracerpid-bypass] hook_wrap2 failed: %d\n", err);
        return -1;
    }

    pr_info("[kpm-tracerpid-bypass] Hook installed successfully\n");
    hook_type = INLINE_CHAIN;
    return 0;
}

static long tracerpid_bypass_exit(void *__user reserved)
{
    if (task_state_sym && hook_type == INLINE_CHAIN) {
        hook_unwrap_remove(task_state_sym, before_task_state, after_task_state, 1);
        pr_info("[kpm-tracerpid-bypass] Hook removed\n");
    }

    return 0;
}

KPM_INIT(tracerpid_bypass_init);
KPM_EXIT(tracerpid_bypass_exit);
