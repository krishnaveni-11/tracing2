from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack
import ctypes as ct
import requests

TARGET_PID = 6001  # replace with your actual PID

bpf_text = """
#include <net/sock.h>
#include <bcc/proto.h>
#include <uapi/linux/ptrace.h>

struct conn_data_t {
    u32 pid;
    char task[TASK_COMM_LEN];
    u16 lport;
    u16 dport;
    u32 laddr;
    u32 daddr;
    u16 family;
};
BPF_PERF_OUTPUT(conn_events);

struct clone_data_t {
    u32 pid;
    u32 tid;
    long ret;
};
BPF_PERF_OUTPUT(clone_events);
BPF_HASH(clone3_ret, u32, struct clone_data_t);

int trace_accept_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %d)
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL)
        return 0;

    struct conn_data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    bpf_probe_read(&data.family, sizeof(data.family), &sk->__sk_common.skc_family);

    if (data.family == AF_INET) {
        bpf_probe_read(&data.lport, sizeof(data.lport), &sk->__sk_common.skc_num);
        u16 dport_net;
        bpf_probe_read(&dport_net, sizeof(dport_net), &sk->__sk_common.skc_dport);
        data.dport = ntohs(dport_net);
        bpf_probe_read(&data.laddr, sizeof(data.laddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
        conn_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int trace_clone3_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %d)
        return 0;

    struct clone_data_t data = {};
    data.pid = pid;
    data.tid = bpf_get_current_pid_tgid();
    u32 tid = data.tid;
    clone3_ret.update(&tid, &data);
    return 0;
}

int trace_clone3_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %d)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct clone_data_t *datap = clone3_ret.lookup(&tid);
    if (datap == 0) {
        return 0;
    }
    datap->ret = PT_REGS_RC(ctx);
    clone_events.perf_submit(ctx, datap, sizeof(*datap));
    clone3_ret.delete(&tid);
    return 0;
}
""" % (TARGET_PID, TARGET_PID, TARGET_PID)

# Setup BPF program
b = BPF(text=bpf_text)
b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")
b.attach_kprobe(event="__x64_sys_clone3", fn_name="trace_clone3_entry")
b.attach_kretprobe(event="__x64_sys_clone3", fn_name="trace_clone3_return")

# Event structures
class ConnData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("task", ct.c_char * 16),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("laddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("family", ct.c_ushort),
    ]

class CloneData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("ret", ct.c_long),
    ]

def inet_ntoa(addr):
    return inet_ntop(AF_INET, pack("I", addr))

def send_log(payload):
    import http.client
    import json

    conn = http.client.HTTPConnection("localhost", 5000)
    headers = {"Content-type": "application/json"}
    body = json.dumps(payload)

    try:
        conn.request("POST", "/log/clone", body, headers)
        response = conn.getresponse()
        if response.status != 200:
            print(f"[WARN] Log not accepted: {response.status} {response.reason}")
    except Exception as e:
        print(f"[ERROR] Failed to send log: {e}")
    finally:
        conn.close()


# Callbacks
def print_conn_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ConnData)).contents
    payload = {
        "type": "conn",
        "pid": event.pid,
        "task": event.task.decode(),
        "laddr": inet_ntoa(event.laddr),
        "lport": event.lport,
        "daddr": inet_ntoa(event.daddr),
        "dport": event.dport
    }
    print("[CONN]", payload)
    send_log(payload)

def print_clone_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(CloneData)).contents
    payload = {
        "type": "clone3",
        "pid": event.pid,
        "tid": event.tid,
        "ret": event.ret
    }
    print("[CLONE3]", payload)
    send_log(payload)

# Register handlers
b["conn_events"].open_perf_buffer(print_conn_event)
b["clone_events"].open_perf_buffer(print_clone_event)

# Poll loop
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Exiting agent...")
        break
