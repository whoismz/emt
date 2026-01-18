# Testing

The project includes usage examples, unit tests, and integration test suites for both eBPF and ptrace modules.

## Structure

```bash
examples/
├── example.rs                      # Basic eBPF tracer usage
├── rwx_monitor.rs                  # RWX monitor self-test
└── rwx_cycle_test.rs               # W-X cycle detection test

tests/
├── integration_test.rs             # eBPF integration tests
├── ptrace_integration_test.rs      # Ptrace integration tests
└── common/
    └── mod.rs                      # Shared test utilities
```

## Running Tests

```bash
# Run all tests (requires root/sudo)
sudo cargo test

# Run unit tests only (no privileges required)
cargo test --lib

# Run eBPF integration tests (requires root/sudo)
sudo cargo test --test integration_test

# Run ptrace integration tests (requires root/sudo)
sudo cargo test --test ptrace_integration_test
```

> Running as a user with CAP_SYS_ADMIN/CAP_BPF/CAP_SYS_PTRACE is sufficient; sudo is shown for simplicity.

## Unit Tests

Unit tests cover the core logic of both modules and can run without root privileges.

### eBPF Module

| File | Tests | Coverage |
|------|-------|----------|
| `src/ebpf/tracer.rs` | 5 | Lifecycle, state management |
| `src/ebpf/bpf_runtime.rs` | 12 | Runtime, event conversion |
| `src/ebpf/event_handler.rs` | 5 | Event processing |
| `src/models.rs` | 5 | Data structures |

### Ptrace Module

| File | Tests | Coverage |
|------|-------|----------|
| `src/ptrace/region.rs` | 32 | TrackedRegion, RegionTracker, W-X transitions |
| `src/ptrace/controller.rs` | 12 | MemoryExecEvent, PtraceController |
| `src/ptrace/monitor.rs` | 15 | RwxMonitor, RwxMonitorBuilder |
| `src/ptrace/remote_syscall.rs` | 10 | SyscallResult, RegisterSnapshot |

Run unit tests:

```bash
cargo test --lib
```

Expected output:

```
running 93 tests
...
test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Integration Tests

### eBPF Integration Tests

Tests the eBPF-based tracer with real memory operations.

**Test Cases:**

1. **Self-Tracing Memory Operations** (`test_trace_self_memory_operations`)
   - Traces the current process's memory operations
   - Verifies detection of mmap and mprotect syscalls
   - Validates captured memory contents against expected patterns

Run:

```bash
sudo cargo test --test integration_test
```

### Ptrace Integration Tests

Tests the ptrace-based RWX monitor with real child processes.

**Test Cases:**

1. **Captures Execution** (`test_rwx_monitor_captures_execution`)
   - Spawns a child process that allocates RWX memory
   - Verifies the monitor captures the W→X transition
   - Validates captured code bytes match expected pattern

2. **W-X Cycles** (`test_rwx_monitor_wx_cycles`)
   - Spawns a child that performs multiple write-then-execute cycles
   - Verifies multiple captures from the same region
   - Validates capture sequence numbers increment correctly

3. **Stop While Running** (`test_rwx_monitor_stop_while_running`)
   - Tests graceful shutdown while target is still running
   - Verifies monitor state after stop

4. **Invalid PID** (`test_rwx_monitor_invalid_pid`)
   - Tests error handling for non-existent PIDs

5. **Double Start** (`test_rwx_monitor_double_start`)
   - Tests that starting an already-running monitor fails correctly

Run:

```bash
sudo cargo test --test ptrace_integration_test
```

Expected output:

```
running 5 tests
test test_rwx_monitor_invalid_pid ... ok
test test_rwx_monitor_captures_execution ... ok
test test_rwx_monitor_wx_cycles ... ok
test test_rwx_monitor_stop_while_running ... ok
test test_rwx_monitor_double_start ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Extending Tests

### Adding eBPF Integration Tests

Add a new test function in `tests/integration_test.rs`:

```rust
#[test]
fn test_new_feature() {
    let mut tracer = Tracer::new(target_pid);
    tracer.start().unwrap();

    // Perform memory operations
    do_memory_operations();

    let pages = tracer.stop().unwrap();

    // Verify results
    assert_eq!(pages.len(), expected_count);
}
```

### Adding Ptrace Integration Tests

Add a new test function in `tests/ptrace_integration_test.rs`:

```rust
#[test]
fn test_new_ptrace_feature() {
    // Compile and spawn a test program
    let bin_path = compile_c_program(MY_TEST_PROGRAM, "test_name").unwrap();
    let mut child = Command::new(&bin_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let child_pid = child.id() as i32;

    // Start monitor
    let mut monitor = RwxMonitorBuilder::new(child_pid).build();
    monitor.start().unwrap();

    // Collect events
    let mut events = Vec::new();
    while monitor.is_running() {
        if let Some(event) = monitor.try_recv_event() {
            events.push(event);
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Cleanup and verify
    let _ = monitor.stop();
    cleanup_binary(&bin_path);

    assert!(!events.is_empty());
}
```

### Adding Unit Tests

Add tests in the corresponding source file within a `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_function() {
        // Test implementation
    }
}
```

<a href="#top">Back to top</a>