#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/mman.h>

struct memory_event {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
};

// define a structure for syscall arguments
struct syscall_ctx {
    __u64 padding;
    __u64 id;
    __u64 args[6];
};

// map to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

// mmap syscall
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_enter(struct syscall_ctx *ctx)
{
    struct memory_event event = {};
    
    event.addr = ctx->args[0];
    event.length = ctx->args[1];
    
    // if it is executable
    __u64 prot = ctx->args[2];
    if (!(prot & PROT_EXEC))
        return 0;
        
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 0;  // map event
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// mprotect syscall (changing memory protection)
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect_enter(struct syscall_ctx *ctx)
{
    struct memory_event event = {};
    
    event.addr = ctx->args[0];
    event.length = ctx->args[1];
    
    __u64 prot = ctx->args[2];
    if (!(prot & PROT_EXEC))
        return 0;
        
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 2;  // protection change
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// munmap syscall
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap_enter(struct syscall_ctx *ctx)
{
    struct memory_event event = {};
    
    event.addr = ctx->args[0];
    event.length = ctx->args[1];
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 1;  // unmap event
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
