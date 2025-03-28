/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Bypass advanced debugger detection techniques");

static char *local_strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;

    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            ++h;
            ++n;
        }
        if (!*n) return (char *)haystack;
        ++haystack;
    }
    return NULL;
}

void before_ptrace(hook_fargs4_t *args, void *udata) {
    pr_info("[anti-debug] ptrace() spoofed\n");
    args->ret = 0;
}

asmlinkage long fake_getppid(unsigned long a1, unsigned long a2, unsigned long a3,
                             unsigned long a4, unsigned long a5, unsigned long a6) {
    pr_info("[anti-debug] getppid() spoofed\n");
    return 1;
}

void before_openat(hook_fargs4_t *args, void *udata) {
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256];
    for (int i = 0; i < 256; i++) buf[i] = '\0';

    if (compat_strncpy_from_user(buf, filename, sizeof(buf)) <= 0) return;

    if (local_strstr(buf, "/proc/self/status") ||
        local_strstr(buf, "/proc/self/pagemap") ||
        local_strstr(buf, "/proc/self/maps") ||
        local_strstr(buf, "/proc/self/mem") ||
        (local_strstr(buf, "/proc/self/task/") &&
         (local_strstr(buf, "/status") ||
          local_strstr(buf, "/comm") ||
          local_strstr(buf, "/mem") ||
          local_strstr(buf, "/pagemap")))) {
        pr_info("[anti-debug] openat() blocked: %s\n", buf);
        args->ret = -ENOENT;
    }
}

void before_readlink(hook_fargs3_t *args, void *udata) {
    const char __user *path = (typeof(path))syscall_argn(args, 0);
    char buf[256];
    for (int i = 0; i < 256; i++) buf[i] = '\0';

    if (compat_strncpy_from_user(buf, path, sizeof(buf)) <= 0) return;

    if (local_strstr(buf, "/proc/self/exe") || local_strstr(buf, "maps")) {
        pr_info("[anti-debug] readlink() blocked: %s\n", buf);
        args->ret = -ENOENT;
    }
}

void after_read(hook_fargs3_t *args, void *udata) {
    ssize_t ret = args->ret;
    if (ret <= 0 || ret >= 512) return;

    char __user *ubuf = (char __user *)args->local.data1;
    char kbuf[512];
    for (int i = 0; i < 512; i++) kbuf[i] = '\0';

    if (compat_strncpy_from_user(kbuf, ubuf, ret) <= 0) return;

    for (int i = 0; i < ret - 10; i++) {
        if (kbuf[i] == 'T' && !__builtin_memcmp(&kbuf[i], "TracerPid:", 10)) {
            int j = i + 10;
            while (j < ret && kbuf[j] == ' ') j++;
            while (j < ret && kbuf[j] >= '0' && kbuf[j] <= '9') {
                kbuf[j++] = '0';
            }
            compat_copy_to_user(ubuf, kbuf, ret);
            pr_info("[anti-debug] TracerPid spoofed in read()\n");
            break;
        }
    }
}

static long anti_debug_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[anti-debug] init\n");

    hook_err_t err = 0;
    err |= inline_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);
    err |= fp_hook_syscalln(__NR_getppid, 6, 0, fake_getppid, 0);
    err |= inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    err |= inline_hook_syscalln(78, 3, before_readlink, 0, 0);  // __NR_readlink = 78
    err |= inline_hook_syscalln(__NR_read, 3, 0, after_read, 0);

    if (err)
        pr_err("[anti-debug] some hooks failed\n");
    else
        pr_info("[anti-debug] all hooks installed\n");

    return 0;
}

static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen) {
    pr_info("[anti-debug] ctl args: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved) {
    pr_info("[anti-debug] exit\n");
    inline_unhook_syscalln(__NR_ptrace, before_ptrace, 0);
    fp_unhook_syscalln(__NR_getppid, 0, fake_getppid);
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    inline_unhook_syscalln(78, before_readlink, 0);
    inline_unhook_syscalln(__NR_read, 0, after_read);
    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
