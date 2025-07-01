# eBPF Internals

Deep dive into [memory_tracer.bpf.c](../src/bpf/memory_tracer.bpf.c)

## Overview

![bpf](./images/bpf.svg)

What can we do with this BPF program:

- Capture syscalls and retrieve their arguments and return values.
- Filter syscalls based on PID and protection flags.
- Dump memory from the target process at target address.
- Send structured memory page by page to userspace.


## Structure

```bash
src/bpf/
├── memory_tracer.bpf.c   # Main BPF program
└── vmlinux.h             # Auto‑generated BTF header
```

## Map Definations

| Map Name        | Type                 | Purpose                       |
| --------------- | -------------------- | ----------------------------- |
| `events`        | BPF_MAP_TYPE_RINGBUF | Event transport to user space |
| `mmap_args`     | BPF_MAP_TYPE_HASH    | Temporary mmap arguments      |
| `mprotect_args` | BPF_MAP_TYPE_HASH    | Temporary mprotect arguments  |


```rust

// Ring buffer map for transferring data to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// Argument storage maps
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
```

## CO‑RE & BTF

- Compiled with `-g -O2 -target bpf` via clang‑15+.
- Relocations resolved at load‑time against `/sys/kernel/btf/vmlinux`.
> Tip: To inspect final byte‑code: `bpftool prog dump xlated id <ID>.`

## Helpers Used

| Helper                     | Purpose                             |
| -------------------------- | ----------------------------------- |
| `bpf_get_current_pid_tgid` | Identify caller thread (TID \| PID) |
| `bpf_map_update_elem`      | Store per-thread syscall arguments  |
| `bpf_map_lookup_elem`      | Retrieve stored args for exit path  |
| `bpf_map_delete_elem`      | Clean up arg cache on error/exit    |
| `bpf_ringbuf_reserve`      | Allocate space in ring buffer       |
| `bpf_ringbuf_submit`       | Published event to userspace        |
| `bpf_ktime_get_ns`         | Timestamp since boot                |
| `bpf_probe_read_user`      | Copy userspace memory               |
| `bpf_repeat`               | Loop execution for specified times  |

## Building

```bash
clang -g -O2 -target bpf -c memory_tracer.bpf.c
```

## Debugging

### Insert `bpf_printk()`

> Supports up to 3 arguments; format specifiers %d, %u, %llu, %s (no floats).

```c
SEC("tracepoint/sys_enter_mprotect")
int enter_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    u64 prot = ctx->args[2];

    /* This line shows up in trace_pipe */
    bpf_printk("mprotect prot=%llu\\n", prot);

    /* ... */
    return 0;
}
```

### View printk stream

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Example output:
```bash
<emt>-1234 [000] d..3 123456.789: mprotect prot=5
```

<a href="#top">Back to top</a>
