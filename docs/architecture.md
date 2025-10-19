# Architecture

High-level overview of interactions between the target process, in-kernel eBPF probes, and the Rust tracer.

## Overview

![architecture](./images/architecture.png)

### 1. Start tracer on target PID, then load BPF object and attach probes.

The tracer validates the target PID existence using `kill(pid, 0)`. Once started, the system monitors all `mmap/mprotect` syscalls for the specific process in the eBPF program.

```rust
// Create a tracer for a target process (PID)
let mut tracer = Tracer::new(target_pid);
tracer.start()?;
```

### 2. Target process calls syscalls like `mmap/mprotect`.

[Example](https://gist.github.com/markmont/dcd20d632fa753438f6fc1b3bb3711ec):

```c
/* source code: https://gist.github.com/markmont/dcd20d632fa753438f6fc1b3bb3711ec */

static uint8_t code[] = {
    0xB8,0x2A,0x00,0x00,0x00,   /* mov  eax,0x2a    */
    0xC3,                       /* ret              */
};

int main(void) {
    const size_t len = sizeof(code);

    /* mmap a region for our code */
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE,  /* No PROT_EXEC */
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p==MAP_FAILED) {
        perror("mmap() failed");
        return 2;
    }

    /* Copy it in (still not executable) */
    memcpy(p, code, len);

    /* Now make it execute-only */
    if (mprotect(p, len, PROT_EXEC) < 0) {
        perror("mprotect failed to mark exec-only");
        return 2;
    }

    /* Go! */
    int (*func)(void) = p;
    printf("(dynamic) code returned %d\n", func());

    return 0;
}
```

### 3 Capture syscall args and returns.

see the source code [memory_tracer.bpf.c](../src/bpf/memory_tracer.bpf.c) and its technical documentation [ebpf.md](ebpf.md).

The kernel component attaches to tracepoints: `sys_enter_mmap`, `sys_exit_mmap`, `sys_enter_munmap`, `sys_enter_mprotect`, and `sys_exit_mprotect`. This dual-phase approach captures complete syscall context including arguments at entry and return values at exit.

### 4. Dump memory page by page at BPF side, and send structured events to userspace via ringbuf map.

```c
// ...
bpf_repeat(num_pages) {
    struct memory_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    event->addr = cur_addr;
    event->length = ONE_PAGE_SIZE;
    event->pid = pid;
    event->event_type = event_type;
    event->timestamp = bpf_ktime_get_ns();

    long ret = bpf_probe_read_user(event->content, ONE_PAGE_SIZE, cur_data);

    if (ret == 0) {
        event->content_size = ONE_PAGE_SIZE;
    } else {
        event->content_size = 0;
    }

    bpf_ringbuf_submit(event, 0);
    // ...
}
```

### 5. Parse received events and get memory pages.

The EventHandler receives raw events and transforms them into structured Page objects. Each page contains the virtual address, size, timestamp, and dumped memory content when available.

<a href="#top">Back to top</a>
