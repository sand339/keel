/*
 * Freestanding Linux/aarch64 Phase 0 probe.
 *
 * This deliberately has no libc or guest package dependencies. It observes
 * network state inside the VM and acts as a minimal MCP client over AF_VSOCK.
 * The production guest relay remains the Rust `keel-mcp-guest` binary.
 */

typedef unsigned long usize;
typedef unsigned int u32;
typedef unsigned short u16;

enum {
    SYS_OPENAT = 56,
    SYS_CLOSE = 57,
    SYS_READ = 63,
    SYS_WRITE = 64,
    SYS_EXIT = 93,
    SYS_SOCKET = 198,
    SYS_CONNECT = 203,
    AT_FDCWD = -100,
    AF_INET = 2,
    AF_VSOCK = 40,
    SOCK_STREAM = 1,
    HOST_CID = 2,
    VSOCK_PORT = 5000,
};

struct sockaddr_vm {
    u16 family;
    u16 reserved;
    u32 port;
    u32 cid;
    unsigned char zero[4];
};

struct sockaddr_in {
    u16 family;
    u16 port;
    u32 address;
    unsigned char zero[8];
};

static long syscall1(long number, long arg0) {
    register long x0 __asm__("x0") = arg0;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

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

static usize string_length(const char *text) {
    usize length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}

static int contains(const char *data, usize length, const char *needle) {
    usize needle_length = string_length(needle);
    if (needle_length == 0 || needle_length > length) {
        return 0;
    }
    for (usize i = 0; i + needle_length <= length; ++i) {
        usize j = 0;
        while (j < needle_length && data[i + j] == needle[j]) {
            ++j;
        }
        if (j == needle_length) {
            return 1;
        }
    }
    return 0;
}

static usize read_file(const char *path, char *buffer, usize capacity) {
    long fd = syscall4(SYS_OPENAT, AT_FDCWD, (long)path, 0, 0);
    if (fd < 0) {
        return 0;
    }
    long count = syscall3(SYS_READ, fd, (long)buffer, (long)capacity);
    syscall1(SYS_CLOSE, fd);
    return count > 0 ? (usize)count : 0;
}

static int write_all(long fd, const char *data, usize length) {
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

static int read_line(long fd, char *buffer, usize capacity) {
    usize offset = 0;
    while (offset + 1 < capacity) {
        long count = syscall3(SYS_READ, fd, (long)(buffer + offset), 1);
        if (count <= 0) {
            return 0;
        }
        if (buffer[offset++] == '\n') {
            buffer[offset] = '\0';
            return 1;
        }
    }
    return 0;
}

static long connect_vsock(void) {
    long fd = syscall3(SYS_SOCKET, AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        return fd;
    }
    struct sockaddr_vm address = {
        .family = AF_VSOCK,
        .reserved = 0,
        .port = VSOCK_PORT,
        .cid = HOST_CID,
        .zero = {0, 0, 0, 0},
    };
    long result =
        syscall3(SYS_CONNECT, fd, (long)&address, sizeof(struct sockaddr_vm));
    if (result < 0) {
        syscall1(SYS_CLOSE, fd);
        return result;
    }
    return fd;
}

static u16 network_port(u16 port) {
    return (u16)((port << 8) | (port >> 8));
}

static u32 network_address(unsigned char a, unsigned char b, unsigned char c,
                           unsigned char d) {
    return (u32)a | ((u32)b << 8) | ((u32)c << 16) | ((u32)d << 24);
}

static int tcp_connects(unsigned char a, unsigned char b, unsigned char c,
                        unsigned char d, u16 port) {
    long fd = syscall3(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }
    struct sockaddr_in address = {
        .family = AF_INET,
        .port = network_port(port),
        .address = network_address(a, b, c, d),
        .zero = {0, 0, 0, 0, 0, 0, 0, 0},
    };
    long result =
        syscall3(SYS_CONNECT, fd, (long)&address, sizeof(struct sockaddr_in));
    syscall1(SYS_CLOSE, fd);
    return result == 0;
}

static usize append(char *output, usize offset, const char *text) {
    usize length = string_length(text);
    for (usize i = 0; i < length; ++i) {
        output[offset + i] = text[i];
    }
    return offset + length;
}

static usize append_bool(char *output, usize offset, int value) {
    return append(output, offset, value ? "true" : "false");
}

static int phase0_probe(void) {
    char observations[4096];
    usize route_length =
        read_file("/proc/net/route", observations, sizeof(observations));
    int has_default_route =
        contains(observations, route_length, "00000000");
    usize dns_length =
        read_file("/etc/resolv.conf", observations, sizeof(observations));
    int has_dns = contains(observations, dns_length, "nameserver") &&
                  !contains(observations, dns_length, "nameserver 0.0.0.0");
    int metadata_reachable = tcp_connects(169, 254, 169, 254, 80);
    int private_reachable = tcp_connects(10, 0, 0, 1, 80);

#ifdef KEEL_FORCE_BROKEN_PREFLIGHT
    has_default_route = 1;
#endif

    long fd = connect_vsock();
    if (fd < 0) {
        return 20;
    }

    const char initialize[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
        "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"keel-phase0\",\"version\":\"0\"}}}\n";
    char response[8192];
    if (!write_all(fd, initialize, sizeof(initialize) - 1) ||
        !read_line(fd, response, sizeof(response))) {
        return 21;
    }

    const char initialized[] =
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
    if (!write_all(fd, initialized, sizeof(initialized) - 1)) {
        return 22;
    }

    char report[1024];
    usize length = 0;
    length = append(
        report, length,
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{"
        "\"name\":\"guest_report\",\"arguments\":{\"probe\":\"keel-phase0\","
        "\"network\":{\"has_default_route\":");
    length = append_bool(report, length, has_default_route);
    length = append(report, length, ",\"has_dns\":");
    length = append_bool(report, length, has_dns);
    length = append(report, length, ",\"metadata_reachable\":");
    length = append_bool(report, length, metadata_reachable);
    length = append(report, length, ",\"private_network_reachable\":");
    length = append_bool(report, length, private_reachable);
    length = append(report, length, "}}}}\n");

    if (!write_all(fd, report, length) ||
        !read_line(fd, response, sizeof(response))) {
        return 23;
    }
    syscall1(SYS_CLOSE, fd);
    if (!contains(response, string_length(response), "\"id\":2") ||
        !contains(response, string_length(response), "keel-phase0")) {
        return 24;
    }

    const char success[] = "keel guest MCP probe passed\n";
    write_all(1, success, sizeof(success) - 1);
    return 0;
}

void _start(void) {
    int result = phase0_probe();
#ifdef KEEL_EXIT_AFTER_PROBE
    syscall1(SYS_EXIT, result);
#else
    if (result != 0) {
        syscall1(SYS_EXIT, result);
    }
    for (;;) {
        __asm__ volatile("wfe");
    }
#endif
}
