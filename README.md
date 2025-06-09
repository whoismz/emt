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
see [example code](./examples/example.rs)
```rust
use emt::Tracer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get target PID from command line arguments or use default
    let target_pid = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1);

    // Create a tracer for a target process (PID)
    let mut tracer = Tracer::new(target_pid);
    tracer.start()?;
    std::thread::sleep(std::time::Duration::from_secs(10));
    let pages = tracer.stop()?;

    // Process the pages you got
    for (i, page) in pages.iter().enumerate() {
        println!(
            "Page {}: 0x{:016x} - 0x{:016x} ({} bytes) at {}",
            i + 1,
            page.addr,
            page.addr + page.size - 1,
            page.size,
            page.timestamp
        );

        // Show first few bytes of memory content if available
        if let Some(content) = &page.content {
            let preview_len = content.len().min(16);
            print!("Content: ");
            for &byte in &content[..preview_len] {
                print!("{:02x} ", byte);
            }
            if content.len() > preview_len {
                print!("...");
            }
            println!();
        }
        println!();
    }

    Ok(())
}
```
