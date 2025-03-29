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

const char *margs = 0;
enum hook_type hook_type = NONE;

// Symbol lookup for __task_pid_nr_ns (optional, for PID logging)
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

void before_openat(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);                  // Directory file descriptor
    const char __user *filename = (typeof(filename))syscall_argn(args, 1); // File path
    int flag = (int)syscall_argn(args, 2);                 // Flags
    umode_t mode = (int)syscall_argn(args, 3);             // Mode

    char buf[256];
    // Copy filename from user space
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    // Check if the file is /proc/self/status
    if (strcmp(buf, PROC_SELF_STATUS) == 0) {
        struct task_struct *task = current;
        pid_t pid = -1;

        // Optionally get PID if symbol is available
        if (__task_pid_nr_ns) {
            pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        }

        pr_info("Detected openat for %s by task %llx, pid %d\n", buf, (uint64_t)task, pid);

        // Return -ENOENT to block access
        args->ret = -ENOENT;
        args->skip_origin = 1; // Skip original syscall

        pr_info("Blocked access to %s\n", buf);
    }
}

static long debugger_bypass_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    pr_info("kpm-debugger-bypass init ..., args: %s\n", margs);

    // Look up __task_pid_nr_ns for PID retrieval (optional)
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    if (__task_pid_nr_ns) {
        pr_info("Found __task_pid_nr_ns at %llx\n", (uint64_t)__task_pid_nr_ns);
    } else {
        pr_info("Could not find __task_pid_nr_ns, PID logging disabled\n");
    }

    if (!margs) {
        pr_warn("No args specified, skip hook\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    // Match demo syntax: support both inline and function pointer hooks
    if (!strcmp("inline_hook", margs)) {
        pr_info("Using inline hook ...\n");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    } else if (!strcmp("function_pointer_hook", margs)) {
        pr_info("Using function pointer hook ...\n");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    } else {
        pr_warn("Unknown args: %s, skip hook\n", margs);
        return 0;
    }

    if (err) {
        pr_err("Hook openat error: %d\n", err);
    } else {
        pr_info("Hook openat success\n");
    }
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
        inline_unhook_syscalln(__NR_openat, before_openat, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat, 0);
    }

    pr_info("Unhooked openat syscall\n");
    return 0;
}

KPM_INIT(debugger_bypass_init);
KPM_CTL0(debugger_bypass_control);
KPM_EXIT(debugger_bypass_exit);
