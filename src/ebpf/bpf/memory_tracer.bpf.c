#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAPPING_ANONYMOUS 0x20
#define ONE_PAGE_SIZE 4096
#define RINGBUF_SIZE (16 * 1024 * 1024) // 16 MiB

// Event types
#define EVENT_TYPE_MMAP 0
#define EVENT_TYPE_MUNMAP 1
#define EVENT_TYPE_MPROTECT 2
#define EVENT_TYPE_EXECVE 3
#define EVENT_TYPE_RWX_MMAP 4      // RWX mmap detected
#define EVENT_TYPE_RWX_MPROTECT 5  // RWX mprotect detected

// Event structure sent via ring buffer
struct memory_event {
    __u64 addr;
    __u64 length;
    __u32 pid;
    __u32 event_type;
    __u64 timestamp;
    __u64 content_size;
    __u64 prot;          // Protection flags for RWX events
    __u8 content[ONE_PAGE_SIZE];
};

// Ring buffer map for transferring data to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// Tracked pids
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} pids SEC(".maps");

// Argument storage for mmap
struct mmap_args_t {
    __u64 addr;
    __u64 length;
    __u64 prot;
    __u64 flags;
    __u64 fd;
    __u64 offset;
    __u8 is_rwx;  // Flag indicating RWX request
};

// Argument storage for mprotect
struct mprotect_args_t {
    __u64 start;
    __u64 length;
    __u64 prot;
    __u8 is_rwx;  // Flag indicating RWX request
};

// Argument storage for execve
struct execve_args_t {
    __u64 filename_ptr;
    __u64 argv_ptr;
    __u64 envp_ptr;
};

// Temporary argument storage maps (key = pid_tgid)
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

// Helper to get pid_tgid
static __always_inline __u64 get_key() { return bpf_get_current_pid_tgid(); }

// Helper to check if a pid is traced
static __always_inline int is_tracked_pids(u32 pid) {
    __u8 *tracked = bpf_map_lookup_elem(&pids, &pid);
    return tracked ? 1 : 0;
}

// Check if protection flags include both WRITE and EXEC (RWX)
static __always_inline int is_rwx(__u64 prot) {
    return ((prot & PROT_WRITE) != 0) && ((prot & PROT_EXEC) != 0);
}

// Dump the memory and send to userspace
static void submit_event(__u64 addr, __u64 len, __u32 pid, __u32 event_type, __u64 prot) {
    if (len == 0)
        return;

    __u64 i;
    bpf_for(i, 0, (len + ONE_PAGE_SIZE - 1) / ONE_PAGE_SIZE) {
        struct memory_event *event =
            bpf_ringbuf_reserve(&events, sizeof(*event), 0);

        if (!event)
            return;

        event->addr = addr + i * ONE_PAGE_SIZE;
        event->length = ONE_PAGE_SIZE;
        event->pid = pid;
        event->event_type = event_type;
        event->timestamp = bpf_ktime_get_ns();
        event->content_size = 0;
        event->prot = prot;

        // Read memory content for map and mprotect events
        if (event_type == EVENT_TYPE_MMAP
            || event_type == EVENT_TYPE_MPROTECT
            || event_type == EVENT_TYPE_RWX_MMAP
            || event_type == EVENT_TYPE_RWX_MPROTECT) {
            long ret = bpf_probe_read_user(event->content, ONE_PAGE_SIZE, (void *)event->addr);
            if (ret == 0) event->content_size = ONE_PAGE_SIZE;
        }

        bpf_ringbuf_submit(event, 0);
    }
}

// Handle mmap entry
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 key = get_key();
    __u32 pid = key >> 32;
    if (!is_tracked_pids(pid))
        return 0;

    __u64 prot = ctx->args[2];

    // Check if this has EXEC permission
    if (!(prot & PROT_EXEC))
        return 0;

    struct mmap_args_t args = {
        .addr   = ctx->args[0],
        .length = ctx->args[1],
        .prot   = ctx->args[2],
        .flags  = ctx->args[3],
        .fd     = ctx->args[4],
        .offset = ctx->args[5],
        .is_rwx = is_rwx(prot) ? 1 : 0,
    };

    bpf_map_update_elem(&mmap_args, &key, &args, BPF_ANY);
    return 0;
}

// Handle mmap exit and emit event
SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    __u64 key = get_key();
    __u32 pid = key >> 32;

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&mmap_args, &key);
        return 0;
    }

    struct mmap_args_t *args = bpf_map_lookup_elem(&mmap_args, &key);
    if (!args)
        return 0;

    // Determine event type based on whether it was RWX
    __u32 event_type = args->is_rwx ? EVENT_TYPE_RWX_MMAP : EVENT_TYPE_MMAP;

    submit_event(ctx->ret, args->length, pid, event_type, args->prot);

    bpf_map_delete_elem(&mmap_args, &key);
    return 0;
}

// Handle mprotect entry
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u64 key = get_key();
    __u32 pid = key >> 32;
    if (!is_tracked_pids(pid))
        return 0;

    __u64 prot = ctx->args[2];

    // Only track if adding EXEC permission
    if (!(prot & PROT_EXEC))
        return 0;

    struct mprotect_args_t args = {
        .start  = ctx->args[0],
        .length = ctx->args[1],
        .prot   = ctx->args[2],
        .is_rwx = is_rwx(prot) ? 1 : 0,
    };

    bpf_map_update_elem(&mprotect_args, &key, &args, BPF_ANY);
    return 0;
}

// Handle mprotect exit and emit event
SEC("tracepoint/syscalls/sys_exit_mprotect")
int trace_exit_mprotect(struct trace_event_raw_sys_exit *ctx) {
    __u64 key = get_key();
    __u32 pid = key >> 32;

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&mprotect_args, &key);
        return 0;
    }

    struct mprotect_args_t *args = bpf_map_lookup_elem(&mprotect_args, &key);
    if (!args)
        return 0;

    __u32 event_type = args->is_rwx ? EVENT_TYPE_RWX_MPROTECT : EVENT_TYPE_MPROTECT;

    submit_event(args->start, args->length, pid, event_type, args->prot);

    bpf_map_delete_elem(&mprotect_args, &key);
    return 0;
}

// Handle munmap
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 addr = ctx->args[0];
    __u64 length = ctx->args[1];

    __u64 key = get_key();
    __u32 pid = key >> 32;

    submit_event(addr, length, pid, EVENT_TYPE_MUNMAP, 0);
    return 0;
}

char _LICENSE[] SEC("license") = "GPL";
