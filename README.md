# emt

A Rust library for tracing executable memory in Linux userspace using eBPF. It tracks syscalls like `mmap`, `mprotect`, and `munmap` to monitor memory regions that gain execution permissions, and dumps their contents for further analysis. This is useful for analyzing JIT compilers, shellcode injection, or dynamic code loading in malware analysis and reverse engineering.

## Requirements
- Rust (latest stable)
- `Clang/LLVM` and `libbpf`
- Linux kernel 5.8 or later with eBPF support
- Root privileges or `CAP_BPF` or `CAP_SYS_ADMIN`

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
1. Target process, see [example.rs](./examples/example.rs)
```bash
# copy the output PID
cargo run --example test_memory_changes
```

2. Tracer process, see [test_memory_changes.rs](./examples/test_memory_changes.rs)
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
