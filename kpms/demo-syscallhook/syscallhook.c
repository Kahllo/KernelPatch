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
#include <linux/sched.h>  // For task_struct
#include <linux/pid.h>    // For pid_t definition

KPM_NAME("kpm-debugger-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Your Name");
KPM_DESCRIPTION("KernelPatch Module to Bypass Debugger Detection");

#define PROC_SELF_STATUS "/proc/self/status"

// Hook function before openat syscall
void before_openat(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);                  // Directory file descriptor
    const char __user *filename = (typeof(filename))syscall_argn(args, 1); // File path
    int flag = (int)syscall_argn(args, 2);                 // Flags
    umode_t mode = (int)syscall_argn(args, 3);             // Mode

    char buf[256];
    // Copy the filename from user space to kernel space
    if (compat_strncpy_from_user(buf, filename, sizeof(buf)) <= 0) {
        return; // Failed to read filename, skip
    }

    // Check if the file being opened is /proc/self/status
    if (strcmp(buf, PROC_SELF_STATUS) == 0) {
        struct task_struct *task = current;  // Get current task
        pid_t pid;

        // Safely get the PID using kernel API if available, otherwise fallback
#ifdef CONFIG_PID_NS
        pid = task_pid_nr(task);  // Preferred method to get PID in modern kernels
#else
        pid = task->pid;          // Fallback for older kernels
#endif

        pr_info("Detected openat for %s by pid %d\n", buf, pid);

        // Option 1: Return -ENOENT (file not found) to prevent opening
        args->ret = -ENOENT;
        args->skip_origin = 1; // Skip the original syscall execution

        // Option 2: Redirect to a fake file (uncomment to use)
        // const char *fake_file = "/proc/self/fake_status";
        // syscall_set_argn(args, 1, (uint64_t)fake_file);

        pr_info("Blocked access to %s for pid %d\n", buf, pid);
    }
}

static long debugger_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm-debugger-bypass init ...\n");

    // Install inline hook for openat syscall
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) {
        pr_err("Failed to hook openat: %d\n", err);
        return err;
    }

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

    // Uninstall the hook
    inline_unhook_syscalln(__NR_openat, before_openat, NULL);

    pr_info("Unhooked openat syscall\n");
    return 0;
}

KPM_INIT(debugger_bypass_init);
KPM_CTL0(debugger_bypass_control);
KPM_EXIT(debugger_bypass_exit);
