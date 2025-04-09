# emt
Linux userspace executable memory tracer

## Usage

```bash
# Build
cargo build

# help
cargo run --bin emt-cli -- --help
> Options:
    -p, --pid PID                Process ID to trace
    -c, --command COMMAND        Command to execute and trace
    -o, --output DIR             Output directory for trace logs (default: ./trace_output)
    -s, --save-content           Save memory content
    -d, --duration SECONDS       Duration to trace in seconds (0 = trace until Ctrl+C)
    -h, --help                   Print help information              Print help information

# example
cargo run --bin emt-cli -- --command "cargo run --example analyzer_diagnostic" --output ./output --duration 5 --save-content
