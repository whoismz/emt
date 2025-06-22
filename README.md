# emt

A Rust library for tracing executable memory in Linux userspace using eBPF.

It tracks syscalls like `mmap` and `mprotect` to monitor memory regions that gain execution permissions, and dumps their contents for further analysis.

## Table of Contents

- [Structure](#structure)
- [Architecture and Design](#architecture-and-design)
  - [Overview](#overview)
  - [eBPF](#ebpf)
- [Requirements](#requirements)
- [Building](#building)
- [Usage](#usage)
- [Example](#example)
- [Limitations and Future work](#limitations-and-future-work)
- [Acknowledgments](#acknowledgments)

## Structure

```bash
emt/
├── src/
│   ├── lib.rs                          # Main library interface
│   ├── tracer.rs                       # Tracer lifecycle management
│   ├── bpf_runtime.rs                  # eBPF program management
│   ├── event_handler.rs                # Memory event processing
│   ├── models.rs                       # Data structures (Event, EventType, Page)
│   ├── error.rs                        # Error types and handling
│   ├── utils.rs                        # Utility functions
│   └── bpf/
│       └── memory_tracer.bpf.c         # eBPF program for kernel-space tracing
├── examples/
│   ├── example.rs                      # Basic usage example
│   ├── test_memory_changes.rs          # Test program with dynamic memory operations
│   └── test_file_mapping.rs            # Test program for file-backed memory mapping
├── tests/
│   ├── integration_test.rs             # Integration tests
│   └── common/
│       └── mod.rs                      # Common test utilities
├── build.rs                            # Build script for this project
├── Cargo.toml                          # Project dependencies and configuration
└── README.md                           # Project documentation
```

## Architecture and Design

### Overview

![arch](./docs/images/architecture.svg)

### eBPF

This eBPF program monitors memory operations in the Linux kernel through tracepoints, capturing:

- Memory mapping operations (`mmap`/`munmap`)
- Protection changes (`mprotect`)

see [memory_tracer.bpf.c](./src/bpf/memory_tracer.bpf.c)

#### eBPF Maps

| Map Name        | Type                 | Purpose                       |
| --------------- | -------------------- | ----------------------------- |
| `events`        | BPF_MAP_TYPE_RINGBUF | Event transport to user space |
| `mmap_args`     | BPF_MAP_TYPE_HASH    | Temporary mmap arguments      |
| `mprotect_args` | BPF_MAP_TYPE_HASH    | Temporary mprotect arguments  |

#### How the eBPF program works

In this situation: `mmap(W) -> writes bytes -> mprotect(X) -> executes`, we now can capture memory events and dump the bytes written without race conditions.

![bpf](./docs/images/bpf.svg)

## Requirements

- Rust
- `Clang/LLVM` and `libbpf`
- Linux kernel with BPF support
- Root privileges or `CAP_BPF` or `CAP_SYS_ADMIN`
- bpftool

This project uses **BPF CO-RE** (Compile Once, Run Everywhere), which requires a `vmlinux.h` file generated from your system’s kernel BTF data. If `src/bpf/vmlinux.h` does not exist, the build script (build.rs) will automatically generate it by running:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## Building

```bash
# clone the emt repository
git clone git@gitlab.eurecom.fr:ma/emt.git && cd emt

# build it
cargo build --release

# test it (sudo for testing current process itself)
sudo cargo test
```

## Usage

```rust
use emt::Tracer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tracer = Tracer::new(2077);

    // start tracing
    tracer.start()?;

    // monitor for a while
    std::thread::sleep(std::time::Duration::from_secs(10));

    // stop and collect results
    let pages = tracer.stop()?;

    // analysis captured pages
    for page in pages {
        println!(
            "0x{:016x} - 0x{:016x} - {} bytes",
            page.addr,
            page.addr + page.size - 1,
            page.size
        );
    }

    Ok(())
}
```

## Example

1. Target process, see [test_memory_changes.rs](./examples/test_memory_changes.rs)

```bash
# copy the output PID
cargo run --example test_memory_changes
```

2. Tracer process, see [example.rs](./examples/example.rs)

```bash
# paste the PID here
sudo cargo run --example example [PID]
```

Expected output:

```
Page 1: 0x00000000158a0000 - 0x00000000158a0fff (4096 bytes) at 2077-10-23 03:39:31.124
Content: 43 79 63 6c 65 20 33 20 2d 20 50 52 45 2d 50 52 ...

Page 2: 0x0000000015910000 - 0x0000000015910fff (4096 bytes) at 2077-10-23 03:39:30.123
Content: 43 79 63 6c 65 20 32 20 2d 20 50 52 45 2d 50 52 ...
```

## Limitations and Future Work

First, when memory regions have both write (W) and execute (X) permissions simultaneously, the tracer cannot detect runtime memory modifications since it only monitors syscall-level operations.

Second, when mmap allocates memory with execute permissions, `bpf_probe_read_user` cannot safely dump memory content without triggering page faults, creating race conditions between allocation.

## Acknowledgments

This project was developed under the supervision of Prof. Aurélien Francillon and Marco Cavenati at EURECOM during Spring 2025.

<a href="#top">Back to top</a>
