#include <linux/sched.h>
#include <net/sock.h>
#include <linux/inet.h>

struct event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 oldstate;
    u8 newstate;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    struct sock *sk = (struct sock *)args->skaddr;
    
    // Filter IPv4 only
    if (sk->__sk_common.skc_family != AF_INET)
        return 0;

    // Filter established connections
    if (args->newstate != TCP_ESTABLISHED)
        return 0;
    // In the BPF program
    if (sk->__sk_common.skc_dport != htons(8081)) 
         return 0;


    struct event_t evt = {
        .saddr = sk->__sk_common.skc_rcv_saddr,
        .daddr = sk->__sk_common.skc_daddr,
        .sport = sk->__sk_common.skc_num,
        .dport = sk->__sk_common.skc_dport,
        .oldstate = args->oldstate,
        .newstate = args->newstate
    };

    // Convert network to host byte order
    evt.saddr = ntohl(evt.saddr);
    evt.daddr = ntohl(evt.daddr);
    evt.sport = ntohs(evt.sport);
    evt.dport = ntohs(evt.dport);

    events.perf_submit(args, &evt, sizeof(evt));

    return 0;
}
