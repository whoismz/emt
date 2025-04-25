#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PROT_EXEC 0x4

struct memory_event {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
};

struct mmap_args_t {
    __u64 addr;
    __u64 length;
    __u64 prot;
    __u64 flags;
    __u64 fd;
    __u64 offset;
    __u64 timestamp;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct mmap_args_t);
} mmap_args SEC(".maps");

// perf map for communication from kernel to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

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

struct sys_exit_mmap_args {
	struct common_header header;
	int __syscall_nr;
	long ret;
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

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_enter_mmap(struct sys_enter_mmap_args *ctx)
{
    bpf_printk("enter_mmap called");

    __u64 prot = ctx->prot;
    if (!(prot & PROT_EXEC)) return 0;

    __u64 key = bpf_get_current_pid_tgid();

    struct mmap_args_t args = {
            .addr = ctx->addr,
            .length = ctx->len,
            .prot = ctx->prot,
            .flags = ctx->flags,
            .fd = ctx->fd,
            .offset = ctx->offset,
            .timestamp = bpf_ktime_get_ns()
    };

    bpf_map_update_elem(&mmap_args, &key, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_exit_mmap(struct sys_exit_mmap_args *ctx)
{
    bpf_printk("exit_mmap called");

    __u64 key = bpf_get_current_pid_tgid();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    long ret = ctx->ret;

    if (ret < 0) {
            bpf_map_delete_elem(&mmap_args, &key);
            return 0;
    }

    struct mmap_args_t *args = bpf_map_lookup_elem(&mmap_args, &key);
    if (!args) return 0;

    struct memory_event event = {
        .addr = ret,
        .length = args->length,
        .pid = pid,
        .event_type = 0,
        .timestamp = args->timestamp
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct sys_enter_mprotect_args *ctx)
{
    __u64 prot = ctx->prot;
    if (!(prot & PROT_EXEC))
        return 0;

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
