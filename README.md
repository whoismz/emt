# emt

A Rust library for tracing executable memory in Linux userspace using eBPF. It tracks syscalls like `mmap`, `mprotect`, and `munmap` to monitor memory regions that gain execution permissions, and dumps their contents for further analysis.

## Requirements
- Linux kernel 5.8+ with eBPF support
- Rust
- `clang`, `llvm`, `libbpf`
- Root privileges or `CAP_SYS_ADMIN` (required to load BPF programs)

## Building
```bash
# clone the emt repository
git clone git@gitlab.eurecom.fr:ma/emt.git && cd emt

# build it
cargo build --release

# test it (sudo for testing current process itself)
sudo cargo test
```

## Usage Example
```rust
use emt::Tracer;

fn main() -> Result<()> {
    // create a new tracer for a target process (PID)
    let mut tracer = Tracer::new(2025);
    
    // start tracing
    tracer.start()?;
    
    std::thread::sleep(std::time::Duration::from_secs(10));

    // stop tracing and get memory pages
    let pages = tracer.stop()?;
    
    // process the pages you got
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
