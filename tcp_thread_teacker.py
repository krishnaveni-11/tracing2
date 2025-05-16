from bcc import BPF
import time
import sys
import ctypes as ct

if len(sys.argv) < 2:
    print("USAGE: tcp_trace.py [PID]")
    exit()
target_pid = int(sys.argv[1])

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

#define TASK_COMM_LEN 16

// Map to store target PID
BPF_HASH(target_pid_map, u32, u32, 1);

struct data_t {
    u32 pid;
    u32 tid;
    int is_user;
    u16 src;
    u16 dest;
    u32 seq;
    char comm[TASK_COMM_LEN];
    char direction[8];
};

BPF_PERF_OUTPUT(events);

static void log_tcp_event(struct pt_regs *ctx, struct sk_buff *skb, const char *direction) {
    u32 key = 0;
    u32 *target_pid = target_pid_map.lookup(&key);
    if (!target_pid) return;  // No PID filter set
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task->tgid != *target_pid) return;  // Filter by PID

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = task->tgid;
    data.tid = task->pid;
    data.is_user = (task->mm != 0);

    struct tcphdr *tcp = (struct tcphdr *)(skb->head + skb->transport_header);
    if (!tcp) return;

    data.src = bpf_ntohs(tcp->source);
    data.dest = bpf_ntohs(tcp->dest);
    data.seq = bpf_ntohl(tcp->seq);
    __builtin_memcpy(data.direction, direction, sizeof(data.direction));
    
    events.perf_submit(ctx, &data, sizeof(data));
}

int trace_tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    log_tcp_event(ctx, skb, "RX");
    return 0;
}

int trace_tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    log_tcp_event(ctx, skb, "RX");
    return 0;
}

int trace_tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask) {
    log_tcp_event(ctx, skb, "TX");
    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_kprobe(event="tcp_v4_rcv", fn_name="trace_tcp_v4_rcv")
b.attach_kprobe(event="tcp_v6_rcv", fn_name="trace_tcp_v6_rcv")
b.attach_kprobe(event="__tcp_transmit_skb", fn_name="trace_tcp_transmit_skb")
b["target_pid_map"][ct.c_uint(0)] = ct.c_uint(target_pid)
print("%-18s %-16s %-6s %-6s %-5s %-8s %-8s %-8s" % 
      ("TIME(s)", "COMM", "PID", "TID", "USER", "SRC", "DEST", "SEQ"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-18.9f %-16s %-6d %-6d %-5s %-8d %-8d %-8d" % (
        time.time(),
        event.comm.decode('utf-8', 'replace'),  # Safely decode process name
        event.pid,
        event.tid,
        "Y" if event.is_user else "N",
        event.src,
        event.dest,
        event.seq
    ))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
