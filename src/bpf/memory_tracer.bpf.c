#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/types.h>

#define PROT_EXEC 0x4

struct memory_event {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
};

// perf event map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

struct trace_event_raw_sys_enter {
    __u64 unused;
    __u64 id;
    __u64 args[6];
};

// mmap
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];
    //if (!(prot & PROT_EXEC))
    //    return 0;

	bpf_printk("mmap called: prot=0x%x", (int)prot);

    struct memory_event event = {};
    event.addr = ctx->args[0];
    event.length = ctx->args[1];
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 0;
    event.timestamp = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// mprotect
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];
    //if (!(prot & PROT_EXEC))
    //    return 0;
	
	bpf_printk("mmap triggered, prot=0x%x", (int)ctx->args[2]);

    struct memory_event event = {};
    event.addr = ctx->args[0];
    event.length = ctx->args[1];
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 2;
    event.timestamp = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// munmap
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx)
{
    struct memory_event event = {};
    event.addr = ctx->args[0];
    event.length = ctx->args[1];
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 1;
    event.timestamp = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

