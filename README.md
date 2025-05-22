# emt
Linux userspace executable memory tracer

## Building
```bash
# clone the emt repository
git clone git@gitlab.eurecom.fr:ma/emt.git && cd emt

# build with sudo for eBPF
sudo cargo build --release
```

## Usage

### Library
```rust
// import the emt library
use emt::Tracer;

fn main() -> Result<()> {
    // create a new tracer for a target process (PID)
    let mut tracer = Tracer::new(2025);
    
    // start tracing
    tracer.start()?;
    
    // wait seconds
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

### Example
```bash
# use it as the target process to mmap, mprotect and unmap some memory
sudo cargo run --example test_memory_changes
```

