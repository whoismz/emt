# emt
Linux userspace executable memory tracer

## Usage

### Build
```bash
cargo build
```
### Help
```bash
sudo cargo run --bin emt-cli -- --help
> Options:
    -p, --pid PID                Process ID to trace
    -c, --command COMMAND        Command to execute and trace
    -o, --output DIR             Output directory for trace logs (default: ./output)
    -s, --save-content           Save memory content
    -d, --duration SECONDS       Duration to trace in seconds (0 = trace until Ctrl+C)
    -h, --help                   Print help information
```

### Example
```bash
// Terminal 1, copy the PID and do not forget to press Enter
sudo cargo run --example test_memory_changes

// Terminal 2, paste the PID
sudo cargo run --bin emt-cli -- -p [PID] -s
```

