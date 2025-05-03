from bcc import BPF
from socket import inet_ntop, AF_INET
import ctypes as ct

bpf_text = """
#include <net/inet_sock.h>
#include <linux/tcp.h>

struct event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

int trace_state(struct pt_regs *ctx, struct sock *sk, int new_state) {
    if (new_state != TCP_ESTABLISHED) return 0;
    if (sk->__sk_common.skc_family != AF_INET) return 0;
    if (sk->sk_type != SOCK_STREAM) return 0;

    struct event_t evt = {};
    
    // Read source port
    bpf_probe_read(&evt.sport, sizeof(evt.sport), 
                  (void *)&sk->__sk_common.skc_num);
    
    // Read destination port
    u16 dport;
    bpf_probe_read(&dport, sizeof(dport), 
                  (void *)&sk->__sk_common.skc_dport);
    evt.dport = ntohs(dport);

    // PORT FILTER: Either source or dest must be 8081
    if (evt.sport != 8081 && evt.dport != 8081) return 0;

    // Read and convert IPs
    bpf_probe_read(&evt.saddr, sizeof(evt.saddr), 
                  (void *)&sk->__sk_common.skc_rcv_saddr);
    evt.saddr = ntohl(evt.saddr);
    
    bpf_probe_read(&evt.daddr, sizeof(evt.daddr), 
                  (void *)&sk->__sk_common.skc_daddr);
    evt.daddr = ntohl(evt.daddr);

    if (evt.saddr == 0 || evt.daddr == 0) return 0;

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16)
    ]

bpf = BPF(text=bpf_text)
bpf.attach_kprobe(event="tcp_set_state", fn_name="trace_state")

def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print(f"Client: {inet_ntop(AF_INET, event.saddr.to_bytes(4, 'big'))}:{event.sport} → "
          f"Server: {inet_ntop(AF_INET, event.daddr.to_bytes(4, 'big'))}:{event.dport}")

bpf["events"].open_perf_buffer(handle_event)
print("Tracing connections with port 8081... Ctrl+C to exit")

try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    pass
