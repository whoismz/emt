## Limitations

1. RWX regions, when memory regions have both write and execute permissions at the same time, the tracer cannot detect runtime memory modifications since it only monitors syscall-level operations for now.

```bash
mmap(RWX) -> write bytes: Memory content modifications not detectable
```

2. page fault, if the memory area has just been mapped (file mapping only, because anonymous mapping will only result in empty pages), it is not possible to trigger a page fault using `bpf_probe_read/write_user()` to read its contents, because the function is non-blocking and cannot handle missing pages.

Linux kernel source code:

```c
// https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c#L174
static __always_inline int
bpf_probe_read_user_common(void *dst, u32 size, const void __user *unsafe_ptr) {
    ...
    ret = copy_from_user_nofault(dst, unsafe_ptr, size);
    ...
}

// https://github.com/torvalds/linux/blob/master/mm/maccess.c#L121
long copy_from_user_nofault(void *dst, const void __user *src, size_t size) {
    ...
    pagefault_disable(); // this disable the pagefault handler.
    ret = __copy_from_user_inatomic(dst, src, size);
    ...
}
```

## Future Work

1. **Page Fault Handling**: Implement controlled page fault triggering in userspace or eBPF-based page fault interception to resolve limitations #2.

2. **Performance Benchmarking**: Compare tracing performance across different eBPF techniques:

    - tracepoint (current)
    - raw_tp/tp_btf
    - kprobe
    - fentry/fexit
