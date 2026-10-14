#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "native_io.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s (errno=%d)\n", \
                __FILE__, __LINE__, #condition, errno); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static unsigned int tests_run;
static volatile sig_atomic_t signals_received;

static void fill_pattern(uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        bytes[i] = (uint8_t)((i * 37U + 11U) & 0xffU);
}

static void write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(fd, bytes + done, length - done);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static int temporary_file(const void *contents, size_t length)
{
    char name[] = "/tmp/native-io-data.XXXXXX";
    int fd = mkstemp(name);
    CHECK(fd >= 0);
    CHECK(unlink(name) == 0);
    write_all(fd, contents, length);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    return fd;
}

static void check_file_unchanged(int fd, const uint8_t *expected, size_t length)
{
    uint8_t *actual = malloc(length + 1);
    CHECK(actual != NULL);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(df_read_full(fd, actual, length + 1) == (ssize_t)length);
    CHECK(memcmp(actual, expected, length) == 0);
    free(actual);
}

static void readback_matches_and_does_not_modify_file(void)
{
    uint8_t bytes[1027];
    struct df_readback_result result;
    fill_pattern(bytes, sizeof(bytes));
    int fd = temporary_file(bytes, sizeof(bytes));
    CHECK(df_verify_fd(fd, 0, bytes, sizeof(bytes), &result) == 0);
    check_file_unchanged(fd, bytes, sizeof(bytes));
    CHECK(close(fd) == 0);
}

static void readback_reports_first_mismatch_across_chunk_boundary(void)
{
    uint8_t bytes[600], expected[600];
    struct df_readback_result result;
    fill_pattern(bytes, sizeof(bytes));
    memcpy(expected, bytes, sizeof(bytes));
    expected[256] ^= 0xffU;
    expected[599] ^= 0xffU;
    int fd = temporary_file(bytes, sizeof(bytes));
    CHECK(df_verify_fd(fd, 0, expected, sizeof(expected), &result) == 1);
    CHECK(result.position == 256);
    CHECK(result.expected == expected[256]);
    CHECK(result.actual == bytes[256]);
    check_file_unchanged(fd, bytes, sizeof(bytes));
    CHECK(close(fd) == 0);
}

static void readback_reports_last_byte_mismatch(void)
{
    uint8_t bytes[513], expected[513];
    struct df_readback_result result;
    fill_pattern(bytes, sizeof(bytes));
    memcpy(expected, bytes, sizeof(bytes));
    expected[512] ^= 0x80U;
    int fd = temporary_file(bytes, sizeof(bytes));
    CHECK(df_verify_fd(fd, 0, expected, sizeof(expected), &result) == 1);
    CHECK(result.position == 512);
    CHECK(result.expected == expected[512]);
    CHECK(result.actual == bytes[512]);
    check_file_unchanged(fd, bytes, sizeof(bytes));
    CHECK(close(fd) == 0);
}

static void readback_handles_nonzero_offset(void)
{
    uint8_t bytes[1027], expected[913];
    struct df_readback_result result;
    const off_t offset = 19;
    fill_pattern(bytes, sizeof(bytes));
    memcpy(expected, bytes + offset, sizeof(expected));
    int fd = temporary_file(bytes, sizeof(bytes));
    CHECK(df_verify_fd(fd, offset, expected, sizeof(expected), &result) == 0);
    expected[sizeof(expected) - 1] ^= 0x40U;
    CHECK(df_verify_fd(fd, offset, expected, sizeof(expected), &result) == 1);
    CHECK(result.position == sizeof(expected) - 1);
    CHECK(result.expected == expected[sizeof(expected) - 1]);
    CHECK(result.actual == bytes[(size_t)offset + sizeof(expected) - 1]);
    check_file_unchanged(fd, bytes, sizeof(bytes));
    CHECK(close(fd) == 0);
}

static void readback_distinguishes_short_file_and_read_error(void)
{
    uint8_t bytes[600];
    struct df_readback_result result;
    fill_pattern(bytes, sizeof(bytes));
    int fd = temporary_file(bytes, 550);
    CHECK(df_verify_fd(fd, 0, bytes, sizeof(bytes), &result) == -1);
    CHECK(result.position == 550);
    CHECK(result.error == 0);
    check_file_unchanged(fd, bytes, 550);
    CHECK(close(fd) == 0);

    errno = 0;
    CHECK(df_verify_fd(-1, 0, bytes, sizeof(bytes), &result) == -1);
    CHECK(result.position == 0);
    CHECK(result.error == EBADF);
    CHECK(errno == EBADF);
}

static void read_full_handles_full_zero_short_and_error(void)
{
    uint8_t bytes[73], actual[74];
    fill_pattern(bytes, sizeof(bytes));
    int fd = temporary_file(bytes, sizeof(bytes));
    CHECK(df_read_full(fd, actual, sizeof(bytes)) == (ssize_t)sizeof(bytes));
    CHECK(memcmp(actual, bytes, sizeof(bytes)) == 0);
    CHECK(df_read_full(fd, actual, sizeof(actual)) == 0);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(df_read_full(fd, actual, sizeof(actual)) == (ssize_t)sizeof(bytes));
    CHECK(memcmp(actual, bytes, sizeof(bytes)) == 0);
    CHECK(df_read_full(fd, actual, 0) == 0);
    CHECK(close(fd) == 0);

    errno = 0;
    CHECK(df_read_full(-1, actual, sizeof(actual)) == -1);
    CHECK(errno == EBADF);
}

static void pause_briefly(void)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 30000000L };
    while (nanosleep(&delay, &delay) < 0)
        CHECK(errno == EINTR);
}

static void count_signal(int signal_number)
{
    (void)signal_number;
    ++signals_received;
}

static struct sigaction install_interrupting_handler(void)
{
    struct sigaction handler, previous;
    memset(&handler, 0, sizeof(handler));
    handler.sa_handler = count_signal;
    CHECK(sigemptyset(&handler.sa_mask) == 0);
    CHECK(sigaction(SIGUSR1, &handler, &previous) == 0);
    signals_received = 0;
    return previous;
}

static void pipe_read_handles_fragmented_data_and_interruption(void)
{
    uint8_t bytes[769], actual[769];
    int pipe_fds[2], status;
    fill_pattern(bytes, sizeof(bytes));
    struct sigaction previous = install_interrupting_handler();
    CHECK(pipe(pipe_fds) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(close(pipe_fds[0]) == 0);
        pause_briefly();
        CHECK(kill(getppid(), SIGUSR1) == 0);
        pause_briefly();
        for (size_t start = 0; start < sizeof(bytes); start += 13) {
            size_t count = sizeof(bytes) - start;
            if (count > 13)
                count = 13;
            write_all(pipe_fds[1], bytes + start, count);
        }
        CHECK(close(pipe_fds[1]) == 0);
        _exit(0);
    }
    CHECK(close(pipe_fds[1]) == 0);
    CHECK(df_read_full(pipe_fds[0], actual, sizeof(actual)) == (ssize_t)sizeof(actual));
    CHECK(memcmp(actual, bytes, sizeof(bytes)) == 0);
    CHECK(df_read_full(pipe_fds[0], actual, sizeof(actual)) == 0);
    CHECK(close(pipe_fds[0]) == 0);
    CHECK(df_wait_for_child(child, &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(signals_received > 0);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
}

static void pipe_read_returns_partial_data_on_eof(void)
{
    uint8_t bytes[17], actual[32];
    int pipe_fds[2];
    fill_pattern(bytes, sizeof(bytes));
    CHECK(pipe(pipe_fds) == 0);
    write_all(pipe_fds[1], bytes, sizeof(bytes));
    CHECK(close(pipe_fds[1]) == 0);
    CHECK(df_read_full(pipe_fds[0], actual, sizeof(actual)) == (ssize_t)sizeof(bytes));
    CHECK(memcmp(actual, bytes, sizeof(bytes)) == 0);
    CHECK(close(pipe_fds[0]) == 0);
}

static void checked_wait_preserves_nonzero_exit_status(void)
{
    int status = -1;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0)
        _exit(17);
    CHECK(df_wait_for_child(child, &status) == 0);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 17);

    status = -1;
    errno = 0;
    CHECK(df_wait_for_child(child, &status) == -1);
    CHECK(errno == ECHILD);
    CHECK(status == 0);
}

static void checked_wait_preserves_signal_status(void)
{
    int status = -1;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(raise(SIGTERM) == 0);
        _exit(99);
    }
    CHECK(df_wait_for_child(child, &status) == 0);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGTERM);
}

static void checked_wait_retries_interruption(void)
{
    int status = -1;
    struct sigaction previous = install_interrupting_handler();
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        pause_briefly();
        CHECK(kill(getppid(), SIGUSR1) == 0);
        pause_briefly();
        _exit(29);
    }
    CHECK(df_wait_for_child(child, &status) == 0);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 29);
    CHECK(signals_received > 0);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
}

static void run_test(const char *name, void (*test)(void))
{
    test();
    ++tests_run;
    printf("PASS %s\n", name);
    fflush(stdout);
}

int main(void)
{
    run_test("readback match and unchanged file", readback_matches_and_does_not_modify_file);
    run_test("readback first mismatch at chunk boundary", readback_reports_first_mismatch_across_chunk_boundary);
    run_test("readback last byte mismatch", readback_reports_last_byte_mismatch);
    run_test("readback nonzero offset", readback_handles_nonzero_offset);
    run_test("readback short file and invalid descriptor", readback_distinguishes_short_file_and_read_error);
    run_test("full, zero, short and error reads", read_full_handles_full_zero_short_and_error);
    run_test("fragmented pipe read with signal interruption", pipe_read_handles_fragmented_data_and_interruption);
    run_test("short pipe read at EOF", pipe_read_returns_partial_data_on_eof);
    run_test("checked wait nonzero exit and ECHILD", checked_wait_preserves_nonzero_exit_status);
    run_test("checked wait signal termination", checked_wait_preserves_signal_status);
    run_test("checked wait signal interruption", checked_wait_retries_interruption);
    printf("%u native I/O tests passed.\n", tests_run);
    return EXIT_SUCCESS;
}
