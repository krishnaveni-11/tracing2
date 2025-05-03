from bcc import BPF

# Set this to the PID you want to trace
TARGET_PID = 3851

bpf_text = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u32 tid;
    long ret;
};

BPF_HASH(clone3_ret, u32, struct data_t);
BPF_PERF_OUTPUT(events);

int trace_clone3_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %d)
        return 0;   // Only trace the target PID

    struct data_t data = {};
    data.pid = pid;
    data.tid = bpf_get_current_pid_tgid();
    u32 tid = data.tid;
    clone3_ret.update(&tid, &data);
    return 0;
}

int trace_clone3_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != %d)
        return 0;   // Only trace the target PID

    u32 tid = bpf_get_current_pid_tgid();
    struct data_t *datap = clone3_ret.lookup(&tid);
    if (datap == 0) {
        return 0;
    }
    datap->ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, datap, sizeof(*datap));
    clone3_ret.delete(&tid);
    return 0;
}
""" % (TARGET_PID, TARGET_PID)

b = BPF(text=bpf_text)
b.attach_kprobe(event="__x64_sys_clone3", fn_name="trace_clone3_entry")
b.attach_kretprobe(event="__x64_sys_clone3", fn_name="trace_clone3_return")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("Parent PID: {}, Parent TID: {}, clone3 return: {}".format(
        event.pid, event.tid, event.ret))

b["events"].open_perf_buffer(print_event)
print("Tracing clone3 for PID %d... Ctrl-C to exit." % TARGET_PID)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
