/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Your Name. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-debugger-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Your Name");
KPM_DESCRIPTION("KernelPatch Module to Bypass Debugger Detection");

#define PROC_SELF_STATUS "/proc/self/status"

// Hook type
enum hook_type hook_type = NONE;

// Function pointer to get PID namespace info (optional, for advanced usage)
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

// Before hook for openat syscall
void before_openat(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    char buf[256];
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    // Check if the file being opened is /proc/self/status
    if (strcmp(buf, PROC_SELF_STATUS) == 0) {
        struct task_struct *task = current;
        pid_t pid = -1;

        if (__task_pid_nr_ns) {
            pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        }

        pr_info("Detected openat on %s by task: %llx, pid: %d\n", buf, task, pid);

        // Option 1: Deny access by setting an error return value
        // args->ret = -EACCES; // Permission denied
        // args->skip_origin = true; // Skip the original syscall

        // Option 2: Redirect to a fake file (more advanced, requires additional logic)
        // For simplicity, we'll just log and allow for now
    }
}

static long debugger_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm-debugger-bypass init ...\n");

    // Look up the address of __task_pid_nr_ns (optional)
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    if (__task_pid_nr_ns) {
        pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);
    } else {
        pr_info("Failed to resolve __task_pid_nr_ns\n");
    }

    // Hook the openat syscall
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) {
        pr_err("Failed to hook openat: %d\n", err);
        return err;
    }

    hook_type = INLINE_CHAIN;
    pr_info("Successfully hooked openat syscall\n");
    return 0;
}

static long debugger_bypass_control(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm-debugger-bypass control, args: %s\n", args);
    return 0;
}

static long debugger_bypass_exit(void *__user reserved)
{
    pr_info("kpm-debugger-bypass exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat, NULL);
        pr_info("Unhooked openat syscall\n");
    }

    return 0;
}

KPM_INIT(debugger_bypass_init);
KPM_CTL0(debugger_bypass_control);
KPM_EXIT(debugger_bypass_exit);
