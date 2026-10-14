#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Ordinary file/pipe operations, kept separate so tests never run the native chain. */
static inline ssize_t df_read_full(int fd, void *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t n = read(fd, (uint8_t *)buffer + total, length - total);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if (n == 0) break;
        total += (size_t)n;
    }
    return (ssize_t)total;
}

static inline int df_wait_for_child(pid_t pid, int *status) {
    *status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) return -1;
    if (waited != pid) {
        errno = ECHILD;
        return -1;
    }
    return 0;
}

struct df_readback_result {
    size_t position;
    uint8_t expected;
    uint8_t actual;
    int error;
};

/* 0: every byte matches; 1: mismatch; -1: read error or EOF (error == 0). */
static inline int df_verify_fd(int fd, off_t offset, const void *expected,
                               size_t length, struct df_readback_result *result) {
    *result = (struct df_readback_result){0};
    const uint8_t *wanted = (const uint8_t *)expected;
    uint8_t observed[256];
    size_t position = 0;
    while (position < length) {
        size_t chunk = length - position;
        if (chunk > sizeof(observed)) chunk = sizeof(observed);
        size_t total = 0;
        while (total < chunk) {
            ssize_t n = pread(fd, observed + total, chunk - total,
                              offset + (off_t)(position + total));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                result->position = position + total;
                result->error = n < 0 ? errno : 0;
                return -1;
            }
            total += (size_t)n;
        }
        for (size_t i = 0; i < chunk; ++i) {
            if (observed[i] != wanted[position + i]) {
                result->position = position + i;
                result->expected = wanted[position + i];
                result->actual = observed[i];
                return 1;
            }
        }
        position += chunk;
    }
    result->position = length;
    return 0;
}
