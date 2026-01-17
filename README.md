# emt

A Rust library for tracing executable memory in Linux userspace using eBPF and ptrace.

- **eBPF-based**: Traces `mmap` and `mprotect` syscalls to capture memory contents when regions gain execute permission
- **ptrace-based**: Intercepts `mmap` and `mprotect` syscalls to enforce W^X, capturing memory on each write-to-execute transition.

## Table of Contents

- [Structure](#structure)
- [Requirements](#requirements)
- [Building](#building)
- [Usage](#usage)
- [Example](#example)
- [Details](#details)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Structure

```bash
emt/
├── src/
│   ├── lib.rs                              # Main library interface
│   ├── models.rs                           # Data structures (Event, EventType, Page)
│   ├── error.rs                            # Error types and handling
│   ├── utils.rs                            # Utility functions
│   ├── ebpf/                               # eBPF-based tracing module
│   │   ├── mod.rs                          # Module exports
│   │   ├── tracer.rs                       # eBPF Tracer lifecycle management
│   │   ├── bpf_runtime.rs                  # eBPF program management
│   │   ├── event_handler.rs                # Memory event processing
│   │   └── bpf/
│   │       ├── memory_tracer.bpf.c         # eBPF program for kernel-space tracing
│   │       └── vmlinux.h                   # Kernel type definitions
│   └── ptrace/                             # Ptrace-based tracing module
│       ├── mod.rs                          # Module exports
│       ├── controller.rs                   # Ptrace controller for process attachment
│       ├── monitor.rs                      # Ptrace tracer implementation
│       ├── region.rs                       # Memory region tracking
│       └── remote_syscall.rs               # Remote syscall injection
├── examples/
│   ├── example.rs                          # Basic eBPF tracer usage
│   ├── rwx_monitor.rs                      # RWX monitor self-test
│   └── rwx_cycle_test.rs                   # W-X cycle detection test
├── tests/
│   ├── integration_test.rs                 # Integration tests
│   └── common/
│       └── mod.rs                          # Common test utilities
├── docs/                                   # Detailed documentation
├── build.rs                                # Build script for this project
├── Cargo.toml                              # Project dependencies and configuration
└── README.md                               # Project documentation
```

## Requirements

- Rust
- Clang/LLVM and libbpf
- Linux kernel with BPF support
- Root privileges or CAP_BPF or CAP_SYS_ADMIN
- bpftool

## Building

```bash
# Install required packages (example for Ubuntu 24.04.2 LTS)
sudo apt install rustup libbpf-dev llvm clang pkg-config

# Clone
git clone git@gitlab.eurecom.fr:ma/emt.git && cd emt

# Build and test
sudo cargo test
```

## Usage

### eBPF-based Tracer

```rust
use emt::Tracer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a tracer for the target process (PID 2077)
    let mut tracer = Tracer::new(2077);

    // Start tracing
    tracer.start()?;

    // Monitor for a while
    std::thread::sleep(std::time::Duration::from_secs(10));

    // Stop and collect results
    let pages = tracer.stop()?;

    // Analyze captured pages
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

### Ptrace-based Tracer

```rust
use emt::RwxMonitorBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a monitor for the target process
    let mut monitor = RwxMonitorBuilder::new(2077).build();

    // Start monitoring
    monitor.start()?;

    // Poll for W→X transition events
    while monitor.is_running() {
        while let Some(event) = monitor.try_recv_event() {
            println!(
                "W→X capture: addr=0x{:x}, len={} bytes",
                event.addr, event.len
            );
            println!("Code bytes: {:02x?}", &event.bytes[..event.bytes.len().min(16)]);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Stop and get final results
    let result = monitor.stop()?;

    Ok(())
}
```

## Example

### eBPF Tracing Example

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

### ptrace Tracing Examples

1. Self-test, see [rwx_monitor.rs](./examples/rwx_monitor.rs):

```bash
cargo run --example rwx_monitor
```

2. W-X cycle detection test, see [rwx_cycle_test.rs](./examples/rwx_cycle_test.rs):

```bash
cargo run --example rwx_cycle_test
```

## Details

- Architecture: see [architecture.md](./docs/architecture.md)

- eBPF: see [ebpf.md](./docs/ebpf.md)

- ptrace: see [ptrace.md](./docs/ptrace.md)

- Testing: see [testing.md](./docs/testing.md)

- CI: see [CI.md](./docs/CI.md)

- Limitations and Future Work: see [limitations_and_future_work.md](./docs/limitations_and_future_work.md)

## Acknowledgments

This project is being developed under the supervision of Prof. Aurélien Francillon and Marco Cavenati at EURECOM.

## License

With the exception of eBPF code, everything is distributed under the terms of the [MIT license](./LICENSE-MIT).

All eBPF code is distributed under the terms of the [GPL-2.0-only](./LICENSE-GPL2).

<a href="#top">Back to top</a>
