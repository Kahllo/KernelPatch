/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Minimal anti-debug KPM module bypassing common detectors");

static enum hook_type hook_type = INLINE_CHAIN;

// === Minimal strstr replacement ===
static char *kpm_strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) h++, n++;
        if (!*n) return (char *)haystack;
    }
    return NULL;
}

// === Safe user string copy (no copy_from_user) ===
static int kpm_copy_str(char *dst, const char __user *src, int maxlen) {
    long ok;
    for (int i = 0; i < maxlen - 1; i++) {
        register long r0 asm("x0") = (long)(dst + i);
        register long r1 asm("x1") = (long)(src + i);
        register long r2 asm("x2") = 1;
        register long r8 asm("x8") = 217; // compat syscall read
        asm volatile("svc #0" : "=r"(ok) : "r"(r0), "r"(r1), "r"(r2), "r"(r8) : "memory");
        if (ok != 0) return -1;
        if (dst[i] == '\0') break;
    }
    dst[maxlen - 1] = '\0';
    return 0;
}

// === ptrace hook ===
void before_ptrace(hook_fargs4_t *args, void *udata) {
    pr_info("[kpm] ptrace bypassed\n");
    args->ret = 0;
}

// === getppid hook ===
asmlinkage long fake_getppid(unsigned long a1, unsigned long a2, unsigned long a3,
                             unsigned long a4, unsigned long a5, unsigned long a6) {
    pr_info("[kpm] getppid bypassed\n");
    return 1;
}

// === openat hook to block tracer files ===
void before_openat(hook_fargs4_t *args, void *udata) {
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[256] = {0};

    if (kpm_copy_str(buf, filename, sizeof(buf)) != 0) return;

    if (kpm_strstr(buf, "/proc/self/status") ||
        kpm_strstr(buf, "/proc/self/maps") ||
        kpm_strstr(buf, "/proc/self/pagemap") ||
        kpm_strstr(buf, "/proc/self/mem")) {
        pr_info("[kpm] blocked openat: %s\n", buf);
        args->ret = -ENOENT;
    }
}

// === INIT ===
static long anti_debug_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[kpm] anti_debug init\n");

    hook_err_t err = 0;
    err |= inline_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);
    err |= fp_hook_syscalln(__NR_getppid, 6, 0, fake_getppid, 0);
    err |= inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);

    if (err)
        pr_err("[kpm] Hook failed: %d\n", err);
    else
        pr_info("[kpm] Hooks installed\n");

    return 0;
}

// === CLEANUP ===
static long anti_debug_exit(void *__user reserved) {
    pr_info("[kpm] anti_debug exit\n");

    inline_unhook_syscalln(__NR_ptrace, before_ptrace, 0);
    fp_unhook_syscalln(__NR_getppid, 0, fake_getppid);
    inline_unhook_syscalln(__NR_openat, before_openat, 0);

    return 0;
}

KPM_INIT(anti_debug_init);
KPM_EXIT(anti_debug_exit);
