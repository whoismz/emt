# emt

A Rust library for tracing executable memory in Linux userspace using eBPF.

It tracks syscalls like `mmap` and `mprotect` to monitor memory regions that gain execution permissions, and dumps their contents for further analysis.

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
├── docs/                               # Detailed documentations
├── build.rs                            # Build script for this project
├── Cargo.toml                          # Project dependencies and configuration
└── README.md                           # Project documentation
```

## Requirements

- Rust
- Clang/LLVM and libbpf
- Linux kernel with BPF support
- Root privileges or CAP_BPF or CAP_SYS_ADMIN
- bpftool

## Building

```bash
# 0. Install required packages (example for Ubuntu 24.04.2 LTS)
sudo apt install rustup libbpf-dev llvm clang pkg-config

# 1. Clone
git clone git@gitlab.eurecom.fr:ma/emt.git && cd emt

# 2. Build and test
sudo cargo test
```

## Usage

```rust
use emt::Tracer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a tracer for the target process (PID 2077)
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

## Details

- Architecture: see [architecture.md](./docs/architecture.md)

- eBPF: see [ebpf.md](./docs/ebpf.md)

- Testing: see [testing.md](./docs/testing.md)

- CI: see [CI.md](./docs/CI.md)

- Limitations and Future Work: see [limitations_and_future_work.md](./docs/limitations_and_future_work.md)

## Acknowledgments

This project is being developed under the supervision of Prof. Aurélien Francillon and Marco Cavenati at EURECOM.

## License

With the exception of eBPF code, everything is distributed under the terms of the [MIT license](./LICENSE-MIT).

All eBPF code is distributed under the terms of the [GPL-2.0-only](./LICENSE-GPL2).

<a href="#top">Back to top</a>
