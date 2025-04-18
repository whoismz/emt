#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/types.h>

#define PROT_EXEC 0x4

/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct mmap_args_t);
} caches SEC(".maps");
*/

// perf event map for communication from kernel to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    // __uint(max_entries, 1024);
} events SEC(".maps");

struct memory_event {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
};

struct common_header {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
};

struct sys_enter_mmap_args {
	struct common_header header;
	int __syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
};

struct sys_enter_mprotect_args {
    struct common_header header;
	int __syscall_nr;
	unsigned long start;
	unsigned long len;
	unsigned long prot;
};

struct sys_enter_munmap_args {
    struct common_header header;
	int __syscall_nr;
	unsigned long addr;
	unsigned long len;
};

// mmap
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct sys_enter_mmap_args *ctx)
{
    __u64 prot = ctx->prot;
    //if (!(prot & PROT_EXEC))
    //    return 0;


	bpf_printk("mmap called");
    struct memory_event event = {};
    event.addr = ctx->addr;
    event.length = ctx->len;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 0;
    event.timestamp = bpf_ktime_get_ns();

    struct memory_event event_test = {
            .addr = 0x1234,
            .length = 4096,
            .pid = bpf_get_current_pid_tgid() >> 32,
            .event_type = 0,
            .timestamp = bpf_ktime_get_ns(),
        };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_test, sizeof(event_test));
    return 0;
}

// mprotect
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct sys_enter_mprotect_args *ctx)
{
    __u64 prot = ctx->prot;
    //if (!(prot & PROT_EXEC))
    //    return 0;

	bpf_printk("mprotect called");

    struct memory_event event = {};
    event.addr = ctx->start;
    event.length = ctx->len;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 2;
    event.timestamp = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// munmap
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct sys_enter_munmap_args *ctx)
{
	bpf_printk("unmmap called");

	struct memory_event event = {};
    event.addr = ctx->addr;
    event.length = ctx->len;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = 1;
    event.timestamp = bpf_ktime_get_ns();

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
