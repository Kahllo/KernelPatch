/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("kpm-tracerpid-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Kahllo");
KPM_DESCRIPTION("Bypass TracerPid from seq_file by hooking task_state");

// Define function pointer
static void (*real_task_state)(struct seq_file *, struct pid_namespace *, struct pid *, struct task_struct *) = NULL;

static void fake_task_state(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *p) {
    struct user_namespace *user_ns = seq_user_ns(m);
    struct group_info *group_info;
    int g, umask = -1;
    struct task_struct *tracer;
    const struct cred *cred;
    pid_t ppid, tpid = 0, tgid, ngid;
    unsigned int max_fds = 0;

    rcu_read_lock();
    ppid = pid_alive(p) ?
        task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;

    tracer = NULL; // Always pretend no tracer attached

    tgid = task_tgid_nr_ns(p, ns);
    ngid = task_numa_group_id(p);
    cred = get_task_cred(p);

    task_lock(p);
    if (p->fs)
        umask = p->fs->umask;
    if (p->files)
        max_fds = files_fdtable(p->files)->max_fds;
    task_unlock(p);
    rcu_read_unlock();

    if (umask >= 0)
        seq_printf(m, "Umask:\t%#04o\n", umask);
    seq_puts(m, "State:\t");
    seq_puts(m, get_task_state(p));

    seq_put_decimal_ull(m, "\nTgid:\t", tgid);
    seq_put_decimal_ull(m, "\nNgid:\t", ngid);
    seq_put_decimal_ull(m, "\nPid:\t", pid_nr_ns(pid, ns));
    seq_put_decimal_ull(m, "\nPPid:\t", ppid);
    seq_put_decimal_ull(m, "\nTracerPid:\t", tpid);  // Always zero
    seq_put_decimal_ull(m, "\nUid:\t", from_kuid_munged(user_ns, cred->uid));
    seq_put_decimal_ull(m, "\t", from_kuid_munged(user_ns, cred->euid));
    seq_put_decimal_ull(m, "\t", from_kuid_munged(user_ns, cred->suid));
    seq_put_decimal_ull(m, "\t", from_kuid_munged(user_ns, cred->fsuid));
    seq_put_decimal_ull(m, "\nGid:\t", from_kgid_munged(user_ns, cred->gid));
    seq_put_decimal_ull(m, "\t", from_kgid_munged(user_ns, cred->egid));
    seq_put_decimal_ull(m, "\t", from_kgid_munged(user_ns, cred->sgid));
    seq_put_decimal_ull(m, "\t", from_kgid_munged(user_ns, cred->fsgid));
    seq_put_decimal_ull(m, "\nFDSize:\t", max_fds);
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
    return 0;
}

static long tracerpid_bypass_exit(void *__user reserved)
{
    if (real_task_state) {
        inline_unhook_function((void *)real_task_state);
        pr_info("[kpm-tracerpid-bypass] Unhooked task_state\n");
    }
    return 0;
}

KPM_INIT(tracerpid_bypass_init);
KPM_EXIT(tracerpid_bypass_exit);
