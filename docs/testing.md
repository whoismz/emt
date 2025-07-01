# Testing

Guide to tests for this project

## Structure

```bash
examples/
├── example.rs                 # Basic usage example
├── test_memory_changes.rs     # Syscall mmap/mprotect operations demo
└── test_file_mapping.rs       # File-backed memory mapping demo

tests/
├── integration_test.rs        # Integration tests
└── common/
    └── mod.rs                 # Shared test utilities
```

## Running Tests

```bash
# Run all tests (requires root/sudo)
sudo cargo test

# Run unit tests (no privileges required)
cargo test --lib

# Run integration tests (requires root/sudo)
sudo cargo test --test integration_test
```
> Running as a user with CAP_SYS_ADMIN/CAP_BPF is sufficient; sudo is shown for simplicity.

## Integration Tests

This integration test suite verifies the functionality of the memory tracer in real-world scenarios, including its lifecycle management and memory operation tracking capabilities.

### Test Cases

#### 1. Tracer Lifecycle Management
- Tests proper initialization, starting, and stopping of the tracer

#### 2. Self-Tracing Memory Operations
- Traces the current process's memory operations
- Verifies detection of:
    - Memory mapping operations (mmap)
    - Memory protection changes (mprotect)
    - Memory writes
- Validates captured memory contents against expected patterns

### How to run

```bash
# Run integration tests (requires root/sudo)
sudo cargo test --test integration_test
```

### Expected Output:

```bash
...
running 2 tests
test test_tracer_lifecycle ... ok
test test_trace_self_memory_operations ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.51s
```

### How to extend the integration test

1. Create a new test function in `tests/integration_test.rs`

```rust
#[test]
fn test_new_feature() {
    // Setup
    let mut tracer = Tracer::new(target_pid);
    
    // Execute
    tracer.start().unwrap();
    
    // Do your operations here
    your_operations();
    
    let pages = tracer.stop().unwrap();
    
    // Verify
    assert_eq!(pages.len(), expected_count);
    // Additional assertions
}
```

2. Add helper functions to `tests/common/mod.rs` for reusable operations

```rust
pub fn your_operations() {
    unsafe {
        // Perform memory operations here...
    }
}
```

<a href="#top">Back to top</a>
