from bcc import BPF
import ctypes
import time
import socket
import struct

def int_to_ip(ip):
    return socket.inet_ntoa(struct.pack("!I", ip)) if ip else "0.0.0.0"

TARGET_PID = 3924
start_ts = time.time()
start_ktime = None

bpf_program = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/inet.h>

struct data_t {{
    u64 pid;
    u64 tid;
    u64 ts;
    u32 uid;
    int fd;
    int bytes;
    char comm[TASK_COMM_LEN];
    char event_type[10];
    u32 port;
    u32 ip;
    u32 local_port;
    u32 local_ip;
}};

BPF_PERF_OUTPUT(events);
BPF_HASH(active_close_fds, u64, int);
BPF_HASH(addr_map, u64, struct sockaddr **);

// ACCEPT ENTRY/EXIT
int trace_accept_entry(struct pt_regs *ctx) {{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != {TARGET_PID}) return 0;

    struct sockaddr **user_sa_ptr = (struct sockaddr **)PT_REGS_PARM2(ctx);
    addr_map.update(&pid_tgid, &user_sa_ptr);
    return 0;
}}

int trace_accept_exit(struct pt_regs *ctx) {{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != {TARGET_PID}) return 0;

    struct data_t data = {{0}};
    data.pid = pid;
    data.tid = pid_tgid & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = (int)PT_REGS_RC(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "ACCEPTEX", 9);

    // Get socket details
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = NULL;
    bpf_probe_read_user(&sk, sizeof(sk), &sock->sk);
    
    if (sk) {{
        // Local address
        bpf_probe_read_kernel(&data.local_port, sizeof(data.local_port), 
                            &sk->__sk_common.skc_num);
        data.local_port = ntohs(data.local_port);
        
        bpf_probe_read_kernel(&data.local_ip, sizeof(data.local_ip), 
                            &sk->__sk_common.skc_rcv_saddr);

        // Remote address
        bpf_probe_read_kernel(&data.port, sizeof(data.port), 
                            &sk->__sk_common.skc_dport);
        data.port = ntohs(data.port);
        
        bpf_probe_read_kernel(&data.ip, sizeof(data.ip), 
                            &sk->__sk_common.skc_daddr);
    }}

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}


// READ ENTRY/EXIT
int trace_read_entry(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != {TARGET_PID}) return 0;

    struct data_t data = {{0}};
    data.pid = pid;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = (int)PT_REGS_PARM1(ctx);
    if (data.fd < 0) data.fd = -1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "READ_ENT", 9);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

int trace_read_exit(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != {TARGET_PID}) return 0;

    struct data_t data = {{0}};
    data.pid = pid;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = (int)PT_REGS_PARM1(ctx);
    data.bytes = PT_REGS_RC(ctx);
    if (data.fd < 0) data.fd = -1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "READ_EX", 8);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

// WRITE ENTRY/EXIT
int trace_write_entry(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != {TARGET_PID}) return 0;

    struct data_t data = {{0}};
    data.pid = pid;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = (int)PT_REGS_PARM1(ctx);
    if (data.fd < 0) data.fd = -1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "WRITE_ENT", 9);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

int trace_write_exit(struct pt_regs *ctx) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != {TARGET_PID}) return 0;

    struct data_t data = {{0}};
    data.pid = pid;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = (int)PT_REGS_PARM1(ctx);
    data.bytes = PT_REGS_RC(ctx);
    if (data.fd < 0) data.fd = -1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "WRITE_EX", 8);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

// CLOSE ENTRY/EXIT
int trace_close_entry(struct pt_regs *ctx) {{
    u64 id = bpf_get_current_pid_tgid();
     
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    if (pid != {TARGET_PID}) return 0;

    int fd = PT_REGS_PARM1(ctx);
    active_close_fds.update(&id, &fd);

    struct data_t data = {{}};
    data.pid = pid;
    data.tid = tid;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = fd;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "CLOSE_EN", 9);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

int trace_close_exit(struct pt_regs *ctx) {{
     u64 id = bpf_get_current_pid_tgid();
    
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    if (pid != {TARGET_PID}) return 0;

    int *fdp = active_close_fds.lookup(&id);
    if (fdp == 0) return 0;

    struct data_t data = {{}};
    data.pid = pid;
    data.tid = tid;
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    data.fd = *fdp;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "CLOSE_EX", 9);

    events.perf_submit(ctx, &data, sizeof(data));
    active_close_fds.delete(&id);
    return 0;
}}
"""

b = BPF(
    text=bpf_program,
    cflags=[
        "-Wno-macro-redefined",
        "-Wno-address-of-packed-member",
        "-Wno-unknown-warning-option"
    ]
)

# Attach syscalls
b.attach_kprobe(event="__x64_sys_accept", fn_name="trace_accept_entry")
b.attach_kretprobe(event="__x64_sys_accept", fn_name="trace_accept_exit")
b.attach_kprobe(event="__x64_sys_accept4", fn_name="trace_accept_entry")
b.attach_kretprobe(event="__x64_sys_accept4", fn_name="trace_accept_exit")

# Read syscalls
read_calls = ["read", "pread64", "recv", "recvfrom", "recvmsg", "readv"]
for call in read_calls:
    b.attach_kprobe(event=b.get_syscall_fnname(call), fn_name="trace_read_entry")
    b.attach_kretprobe(event=b.get_syscall_fnname(call), fn_name="trace_read_exit")

# Write syscalls
write_calls = ["send", "sendto", "sendmsg"]
for call in write_calls:
    b.attach_kprobe(event=b.get_syscall_fnname(call), fn_name="trace_write_entry")
    b.attach_kretprobe(event=b.get_syscall_fnname(call), fn_name="trace_write_exit")

# Close syscalls
b.attach_kprobe(event="__x64_sys_close", fn_name="trace_close_entry")
b.attach_kretprobe(event="__x64_sys_close", fn_name="trace_close_exit")


class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_ulonglong),
        ("tid", ctypes.c_ulonglong),
        ("ts", ctypes.c_ulonglong),
        ("uid", ctypes.c_uint),
        ("fd", ctypes.c_int),
        ("bytes", ctypes.c_int),
        ("comm", ctypes.c_char * 16),
        ("event_type", ctypes.c_char * 10),
        ("port", ctypes.c_uint),
        ("ip", ctypes.c_uint),
        ("local_port", ctypes.c_uint),
        ("local_ip", ctypes.c_uint),
    ]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    label = event.event_type.decode().strip()
    
    # Calculate relative timestamp
    if start_ktime is None:
        rel_ts = 0
    else:
        rel_ts = (event.ts - start_ktime) / 1000000000  # Convert ns to seconds
    
    # Format timestamp
    timestamp = f"{time.strftime('%H:%M:%S', time.localtime())}+{rel_ts:.6f}"
    
    # Base message components
    components = [
        f"[{timestamp}]",  # Add timestamp at the beginning
        f"[{label}] PID {event.pid}",
        f"TID {event.tid}",
        f"UID {event.uid}",
        f"COMM {event.comm.decode().strip()}",
        f"FD {event.fd if event.fd >= 0 else 'INVALID'}"
    ]

    # Handle return values for EXIT events
    if label.endswith("_EX"):
        if "CLOSE_EX" in label:
            components.append(f"RETURNED {'SUCCESS' if event.bytes == 0 else f'ERROR (code={event.bytes})'}")
        else:  # READ_EX/WRITE_EX
            components.append(f"RETURNED {event.bytes} bytes")
    
    # Handle ACCEPT events
    if "ACCEPT" in label:
        components.append(
            f"Remote {int_to_ip(event.ip)}:{event.port} "
            f"Local {int_to_ip(event.local_ip)}:{event.local_port}"
        )

    print(" ".join(components))


print(f"Tracing PID {TARGET_PID}... Ctrl-C to exit")
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

