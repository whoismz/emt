// simple_tracer.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_simple(void *ctx) {
    bpf_printk("Simple mmap trace");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
