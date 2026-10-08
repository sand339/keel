#define _DARWIN_C_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

enum { OUTPUT_CAPACITY = 64 * 1024 };

static void fail(const char *message) {
    perror(message);
    exit(1);
}

static bool contains(const char *output, size_t length, const char *needle) {
    const size_t needle_length = strlen(needle);
    if (needle_length == 0 || needle_length > length) {
        return false;
    }
    for (size_t index = 0; index + needle_length <= length; index++) {
        if (memcmp(output + index, needle, needle_length) == 0) {
            return true;
        }
    }
    return false;
}

static void write_all(int descriptor, const void *buffer, size_t length) {
    const char *bytes = buffer;
    while (length > 0) {
        const ssize_t written = write(descriptor, bytes, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail("write");
        }
        bytes += written;
        length -= (size_t)written;
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s TRUSTED_RUNTIME RENDERER\n", argv[0]);
        return 2;
    }

    int master = -1;
    int slave = -1;
    char slave_name[128] = {0};
    if (openpty(&master, &slave, slave_name, NULL, NULL) != 0) {
        fail("openpty");
    }

    struct termios raw;
    if (tcgetattr(slave, &raw) != 0) {
        fail("tcgetattr");
    }
    cfmakeraw(&raw);
    if (tcsetattr(slave, TCSAFLUSH, &raw) != 0) {
        fail("tcsetattr");
    }
    if (ioctl(slave, TIOCEXCL) != 0) {
        fail("TIOCEXCL");
    }
    if (fchmod(slave, 0) != 0) {
        fail("fchmod tty capability");
    }

    errno = 0;
    const int competing_open = open(slave_name, O_RDWR | O_NOCTTY);
    if (competing_open >= 0 || (errno != EACCES && errno != EBUSY)) {
        fprintf(stderr, "exclusive tty check failed: fd=%d errno=%d\n",
                competing_open, errno);
        return 1;
    }

    const pid_t child = fork();
    if (child < 0) {
        fail("fork");
    }
    if (child == 0) {
        close(master);
        if (dup2(slave, STDIN_FILENO) < 0 ||
            dup2(slave, STDOUT_FILENO) < 0 ||
            dup2(slave, STDERR_FILENO) < 0) {
            fail("dup2");
        }
        if (slave > STDERR_FILENO) {
            close(slave);
        }
        execl(argv[1], argv[1], argv[2], slave_name, (char *)NULL);
        fail("exec trusted runtime");
    }

    close(slave);
    char output[OUTPUT_CAPACITY];
    size_t output_length = 0;
    bool sent_attention = false;
    bool sent_challenge = false;
    int status = 0;

    for (;;) {
        struct pollfd event = {.fd = master, .events = POLLIN};
        const int ready = poll(&event, 1, 3000);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            fail("poll");
        }
        if (ready == 0) {
            fprintf(stderr, "tty proof timed out\n");
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            return 1;
        }
        if ((event.revents & POLLIN) != 0) {
            const ssize_t count =
                read(master, output + output_length,
                     sizeof(output) - output_length);
            if (count > 0) {
                output_length += (size_t)count;
            }
        }

        if (!sent_attention &&
            contains(output, output_length, "TTY_RUNTIME_READY\n")) {
            const unsigned char input[] = {'h', 'i', 0x1d};
            write_all(master, input, sizeof(input));
            sent_attention = true;
        }
        if (!sent_challenge &&
            contains(output, output_length, "KEEL TRUSTED SCREEN\n")) {
            write_all(master, "7KQ2\n", 5);
            sent_challenge = true;
        }

        const pid_t result = waitpid(child, &status, WNOHANG);
        if (result < 0) {
            fail("waitpid");
        }
        if (result == child) {
            break;
        }
        if (output_length == sizeof(output)) {
            fprintf(stderr, "tty proof output exceeded capture capacity\n");
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            return 1;
        }
    }

    close(master);
    const bool passed =
        WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        contains(output, output_length, "\x1b[2J\x1b[H") &&
        contains(output, output_length, "Keel harness TUI") &&
        contains(output, output_length, "RENDERER_NO_TTY=pass") &&
        contains(output, output_length, "KEEL TRUSTED SCREEN") &&
        contains(output, output_length, "APPROVED") &&
        !contains(output, output_length, "DROPPED_GUEST_FRAME");
    if (!passed) {
        fwrite(output, 1, output_length, stderr);
        fprintf(stderr, "\ntty proof assertions failed (status=%d)\n", status);
        return 1;
    }

    puts("exclusive raw tty ownership: PASS");
    puts("renderer inherited no tty: PASS");
    puts("harness TUI frame rendered: PASS");
    puts("secure-attention takeover and frame drop: PASS");
    return 0;
}
