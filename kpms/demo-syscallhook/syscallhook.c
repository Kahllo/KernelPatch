/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/string.h>

#ifndef __NR_readlink
#define __NR_readlink 89
#endif

KPM_NAME("anti_debug_kpm");
KPM_VERSION("2.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Bypass advanced debugger detection techniques");

static enum hook_type hook_type = INLINE_CHAIN;

// ========== ptrace hook ==========
void before_ptrace(hook_fargs4_t *args, void *udata)
{
    pr_info("[anti-debug] ptrace called, spoofing return\n");
    args->ret = 0;
    return;
}

// ========== getppid hook ==========
asmlinkage long fake_getppid(unsigned long arg1, unsigned long arg2, unsigned long arg3,
                             unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
    pr_info("[anti-debug] getppid spoofed\n");
    return 1;
}

// ========== openat hook ==========
void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256] = {0};

    if (compat_strncpy_from_user(buf, filename, sizeof(buf)) <= 0)
        return;

    if (buf[0] &&
        (strstr(buf, "/proc/self/status") ||
         strstr(buf, "/proc/self/task/") && (
             strstr(buf, "/status") ||
             strstr(buf, "/comm") ||
             strstr(buf, "/mem") ||
             strstr(buf, "/pagemap")) ||
         strstr(buf, "/proc/self/pagemap") ||
         strstr(buf, "/proc/self/mem") ||
         strstr(buf, "/proc/self/maps")))
    {
        pr_info("[anti-debug] blocked openat path: %s\n", buf);
        args->ret = -ENOENT;
    }
}

// ========== readlink hook ==========
void before_readlink(hook_fargs3_t *args, void *udata)
{
    const char __user *path = (typeof(path))syscall_argn(args, 0);
    char buf[256] = {0};

    if (compat_strncpy_from_user(buf, path, sizeof(buf)) <= 0)
        return;

    if (strstr(buf, "/proc/self/exe") || strstr(buf, "maps"))
    {
        pr_info("[anti-debug] blocked readlink path: %s\n", buf);
        args->ret = -ENOENT;
    }
}

// ========== read after-hook (TracerPid patch) ==========
void after_read(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = args->ret;
    if (ret <= 0)
        return;

    char __user *user_buf = (char __user *)args->local.data1;
    char kbuf[512] = {0};

    if (ret >= sizeof(kbuf))
        return;

    if (compat_strncpy_from_user(kbuf, user_buf, ret) <= 0)
        return;

    for (int i = 0; i < ret - 10; i++)
    {
        if (!memcmp(&kbuf[i], "TracerPid:", 10))
        {
            int j = i + 10;
            while (j < ret && kbuf[j] == ' ')
                j++;
            while (j < ret && kbuf[j] >= '0' && kbuf[j] <= '9')
            {
                kbuf[j++] = '0';
            }
            pr_info("[anti-debug] TracerPid spoofed in read()\n");
            compat_copy_to_user(user_buf, kbuf, ret);
            break;
        }
    }
}

// ========== INIT ==========
static long anti_debug_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] init\n");

    hook_err_t err = 0;

    err |= inline_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);
    err |= fp_hook_syscalln(__NR_getppid, 6, 0, fake_getppid, 0);
    err |= inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    err |= inline_hook_syscalln(__NR_readlink, 3, before_readlink, 0, 0);
    err |= inline_hook_syscalln(__NR_read, 3, 0, after_read, 0);

    if (err)
        pr_err("[anti-debug] One or more hooks failed\n");
    else
        pr_info("[anti-debug] All hooks installed\n");

    return 0;
}

// ========== CTL & EXIT ==========
static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[anti-debug] control command: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved)
{
    pr_info("[anti-debug] exit, unhooking syscalls\n");

    inline_unhook_syscalln(__NR_ptrace, before_ptrace, 0);
    fp_unhook_syscalln(__NR_getppid, 0, fake_getppid);
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    inline_unhook_syscalln(__NR_readlink, before_readlink, 0);
    inline_unhook_syscalln(__NR_read, 0, after_read);

    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
