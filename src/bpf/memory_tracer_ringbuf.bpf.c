#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PROT_EXEC 0x4
#define MAX_SNAPSHOT_SIZE 256

struct memory_event {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
} __attribute__((packed));

struct memory_snapshot {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
    __u8  content[MAX_SNAPSHOT_SIZE];
} __attribute__((packed));

struct mmap_args_t {
    __u64 addr;
    __u64 length;
    __u64 prot;
    __u64 flags;
    __u64 fd;
    __u64 offset;
} __attribute__((packed));

struct mprotect_args_t {
    __u64 start;
    __u64 length;
    __u64 prot;
} __attribute__((packed));

struct execve_args_t {
    __u64 filename_ptr;
    __u64 argv_ptr;
    __u64 envp_ptr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct mmap_args_t);
} mmap_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct mprotect_args_t);
} mprotect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct execve_args_t);
} execve_args SEC(".maps");

// perf event map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// ringbuf map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} snapshots SEC(".maps");

static void capture_snapshot(struct pt_regs *ctx, __u64 addr, __u64 len, __u32 pid, __u32 event_type) {
    // if (len < 16) return;

    __u64 capture_len = len > MAX_SNAPSHOT_SIZE ? MAX_SNAPSHOT_SIZE : len;

    struct memory_snapshot *snap = bpf_ringbuf_reserve(&snapshots,
        sizeof(*snap), 0);
    if (!snap) return;

    snap->addr = addr;
    snap->length = len;
    snap->pid = pid;
    snap->event_type = event_type;
    snap->timestamp = bpf_ktime_get_ns();

    long ret = bpf_probe_read_user(
        snap->content,
        capture_len,
        (void *)addr
    );

    if (ret == 0) {
        bpf_ringbuf_submit(snap, 0);
    } else {
        bpf_ringbuf_discard(snap, 0);
    }
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    // bpf_printk("enter_mmap called");

    // __u64 prot = ctx->args[2];
    // if (!(prot & PROT_EXEC)) return 0;

    __u64 key = bpf_get_current_pid_tgid();

    struct mmap_args_t args = {
        .addr = ctx->args[0],
        .length = ctx->args[1],
        .prot = ctx->args[2],
        .flags = ctx->args[3],
        .fd = ctx->args[4],
        .offset = ctx->args[5]
    };

    bpf_map_update_elem(&mmap_args, &key, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    // bpf_printk("exit_mmap called");

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
        .timestamp = bpf_ktime_get_ns()
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    capture_snapshot(ctx, ctx->ret, args->length, pid, 0);
    bpf_map_delete_elem(&mmap_args, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    // bpf_printk("mprotect called");

    // __u64 prot = ctx->args[2];
    // if (!(prot & PROT_EXEC)) return 0;

    __u64 key = bpf_get_current_pid_tgid();

    struct mprotect_args_t args = {
            .start = ctx->args[0],
            .length = ctx->args[1],
            .prot = ctx->args[2],
    };

    bpf_map_update_elem(&mprotect_args, &key, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int trace_exit_mprotect(struct trace_event_raw_sys_exit *ctx) {
    // bpf_printk("mprotect called");

    __u64 key = bpf_get_current_pid_tgid();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (ctx->ret != 0) {
        bpf_map_delete_elem(&mprotect_args, &key);
        return 0;
    }

    struct mprotect_args_t *args = bpf_map_lookup_elem(&mprotect_args, &key);
    if (!args) return 0;

    struct memory_event event = {
        .addr = args->start,
        .length = args->length,
        .pid = pid,
        .event_type = 2,
        .timestamp = bpf_ktime_get_ns()
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    capture_snapshot(ctx, args->start, args->length, pid, 2);
    bpf_map_delete_elem(&mprotect_args, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx) {
	// bpf_printk("unmmap called");

	struct memory_event event = {
        .addr = ctx->args[0],
        .length = ctx->args[1],
        .pid = bpf_get_current_pid_tgid() >> 32,
        .event_type = 1,
        .timestamp = bpf_ktime_get_ns()
	};

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 key = bpf_get_current_pid_tgid();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct execve_args_t args = {
        .filename_ptr = ctx->args[0],
        .argv_ptr = ctx->args[1],
        .envp_ptr = ctx->args[2]
    };

    bpf_map_update_elem(&execve_args, &key, &args, BPF_ANY);

    struct memory_event event = {
        .addr = 0,
        .length = 0,
        .pid = pid,
        .event_type = 3,
        .timestamp = bpf_ktime_get_ns()
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// if execve works, then this tracepoint will not be called
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    __u64 key = bpf_get_current_pid_tgid();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    long ret = ctx->ret;

    if (ret < 0) {
        bpf_map_delete_elem(&execve_args, &key);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
