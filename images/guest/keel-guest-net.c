/*
 * Freestanding Linux/aarch64 guest DNS and TCP-to-vsock relay.
 *
 * Build one DNS process with KEEL_DNS, or one TCP relay with
 * KEEL_LOCAL_PORT and KEEL_VSOCK_PORT. The image runs separate relay
 * processes so a guest connection can never select its host-side service.
 */

typedef unsigned long usize;
typedef unsigned int u32;
typedef unsigned short u16;

enum {
    SYS_CLOSE = 57,
    SYS_READ = 63,
    SYS_WRITE = 64,
    SYS_PPOLL = 73,
    SYS_EXIT = 93,
    SYS_SOCKET = 198,
    SYS_BIND = 200,
    SYS_LISTEN = 201,
    SYS_ACCEPT = 202,
    SYS_CONNECT = 203,
    SYS_SENDTO = 206,
    SYS_RECVFROM = 207,
    SYS_CLONE = 220,
    SYS_WAIT4 = 260,
    AF_INET = 2,
    AF_VSOCK = 40,
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    HOST_CID = 2,
    POLLIN = 1,
    WNOHANG = 1,
    SIGCHLD = 17,
};

struct sockaddr_in {
    u16 family;
    u16 port;
    u32 address;
    unsigned char zero[8];
};

struct sockaddr_vm {
    u16 family;
    u16 reserved;
    u32 port;
    u32 cid;
    unsigned char zero[4];
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

static long syscall1(long number, long arg0) {
    register long x0 __asm__("x0") = arg0;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

#ifndef KEEL_DNS
static long syscall2(long number, long arg0, long arg1) {
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}
#endif

static long syscall3(long number, long arg0, long arg1, long arg2) {
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory"
    );
    return x0;
}

#ifndef KEEL_DNS
static long syscall5(long number, long arg0, long arg1, long arg2, long arg3,
                     long arg4) {
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = arg3;
    register long x4 __asm__("x4") = arg4;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "memory"
    );
    return x0;
}
#endif

#ifndef KEEL_DNS
static long syscall4(long number, long arg0, long arg1, long arg2, long arg3) {
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = arg3;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory"
    );
    return x0;
}
#endif

#ifdef KEEL_DNS
static long syscall6(long number, long arg0, long arg1, long arg2, long arg3,
                     long arg4, long arg5) {
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = arg3;
    register long x4 __asm__("x4") = arg4;
    register long x5 __asm__("x5") = arg5;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory"
    );
    return x0;
}
#endif

static u16 network_port(u16 port) {
    return (u16)((port << 8) | (port >> 8));
}

static u32 network_address(unsigned char a, unsigned char b, unsigned char c,
                           unsigned char d) {
    return (u32)a | ((u32)b << 8) | ((u32)c << 16) | ((u32)d << 24);
}

#ifndef KEEL_DNS
static int write_all(long fd, const unsigned char *data, usize length) {
    usize offset = 0;
    while (offset < length) {
        long count =
            syscall3(SYS_WRITE, fd, (long)(data + offset), (long)(length - offset));
        if (count <= 0) {
            return 0;
        }
        offset += (usize)count;
    }
    return 1;
}
#endif

#ifdef KEEL_DNS
static usize question_length(const unsigned char *query, usize length) {
    usize offset = 12;
    while (offset < length) {
        unsigned char label = query[offset++];
        if (label == 0) {
            return offset + 4 <= length ? offset + 4 : 0;
        }
        if ((label & 0xc0) != 0 || offset + label > length) {
            return 0;
        }
        offset += label;
    }
    return 0;
}

static int serve_dns(void) {
    long fd = syscall3(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 10;
    }
    struct sockaddr_in address = {
        .family = AF_INET,
        .port = network_port(53),
        .address = network_address(127, 0, 0, 1),
        .zero = {0, 0, 0, 0, 0, 0, 0, 0},
    };
    if (syscall3(SYS_BIND, fd, (long)&address, sizeof(address)) < 0) {
        return 11;
    }

    for (;;) {
        unsigned char query[512];
        unsigned char response[528];
        unsigned char peer[128];
        u32 peer_length = sizeof(peer);
        long count = syscall6(SYS_RECVFROM, fd, (long)query, sizeof(query), 0,
                              (long)peer, (long)&peer_length);
        if (count < 12) {
            continue;
        }
        usize question_end = question_length(query, (usize)count);
        if (question_end == 0 || question_end + 16 > sizeof(response)) {
            continue;
        }
        for (usize index = 0; index < question_end; ++index) {
            response[index] = query[index];
        }
        response[2] = 0x81;
        response[3] = 0x80;
        response[4] = 0;
        response[5] = 1;
        response[6] = 0;
        response[7] = 1;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;

        usize offset = question_end;
        const unsigned char answer[] = {
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x3c, 0x00, 0x04, 10,   0,    0,    1,
        };
        for (usize index = 0; index < sizeof(answer); ++index) {
            response[offset++] = answer[index];
        }
        syscall6(SYS_SENDTO, fd, (long)response, (long)offset, 0, (long)peer,
                 peer_length);
    }
}
#else
static long connect_host(void) {
    long fd = syscall3(SYS_SOCKET, AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        return fd;
    }
    struct sockaddr_vm address = {
        .family = AF_VSOCK,
        .reserved = 0,
        .port = KEEL_VSOCK_PORT,
        .cid = HOST_CID,
        .zero = {0, 0, 0, 0},
    };
    if (syscall3(SYS_CONNECT, fd, (long)&address, sizeof(address)) < 0) {
        syscall1(SYS_CLOSE, fd);
        return -1;
    }
    return fd;
}

static void relay(long guest, long host) {
    unsigned char buffer[16384];
    struct pollfd descriptors[2] = {
        {.fd = (int)guest, .events = POLLIN, .revents = 0},
        {.fd = (int)host, .events = POLLIN, .revents = 0},
    };
    for (;;) {
        descriptors[0].revents = 0;
        descriptors[1].revents = 0;
        if (syscall5(SYS_PPOLL, (long)descriptors, 2, 0, 0, 0) <= 0) {
            return;
        }
        for (int index = 0; index < 2; ++index) {
            if ((descriptors[index].revents & POLLIN) == 0) {
                continue;
            }
            long source = index == 0 ? guest : host;
            long target = index == 0 ? host : guest;
            long count = syscall3(SYS_READ, source, (long)buffer, sizeof(buffer));
            if (count <= 0 || !write_all(target, buffer, (usize)count)) {
                return;
            }
        }
    }
}

static int serve_tcp(void) {
    long listener = syscall3(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return 20;
    }
    struct sockaddr_in address = {
        .family = AF_INET,
        .port = network_port(KEEL_LOCAL_PORT),
        .address = network_address(10, 0, 0, 1),
        .zero = {0, 0, 0, 0, 0, 0, 0, 0},
    };
    if (syscall3(SYS_BIND, listener, (long)&address, sizeof(address)) < 0 ||
        syscall2(SYS_LISTEN, listener, 16) < 0) {
        return 21;
    }
    for (;;) {
        while (syscall4(SYS_WAIT4, -1, 0, WNOHANG, 0) > 0) {
        }
        long guest = syscall3(SYS_ACCEPT, listener, 0, 0);
        if (guest < 0) {
            continue;
        }
        long child = syscall5(SYS_CLONE, SIGCHLD, 0, 0, 0, 0);
        if (child == 0) {
            syscall1(SYS_CLOSE, listener);
            long host = connect_host();
            if (host >= 0) {
                relay(guest, host);
                syscall1(SYS_CLOSE, host);
            }
            syscall1(SYS_CLOSE, guest);
            syscall1(SYS_EXIT, 0);
            for (;;) {
                __asm__ volatile("wfe");
            }
        }
        if (child < 0) {
            long host = connect_host();
            if (host >= 0) {
                relay(guest, host);
                syscall1(SYS_CLOSE, host);
            }
        }
        syscall1(SYS_CLOSE, guest);
    }
}
#endif

void _start(void) {
#ifdef KEEL_DNS
    int result = serve_dns();
#else
    int result = serve_tcp();
#endif
    syscall1(SYS_EXIT, result);
    for (;;) {
        __asm__ volatile("wfe");
    }
}
