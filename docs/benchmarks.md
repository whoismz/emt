# Benchmarks

The project includes benchmarks using [Criterion.rs](https://github.com/bheisler/criterion.rs) to measure performance of critical operations.

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark suite
cargo bench --bench region_benchmarks
cargo bench --bench event_benchmarks

# Run with specific filter
cargo bench -- tracker_operations

# Run without HTML report generation
cargo bench -- --noplot
```

## Benchmark Suites

### Region Benchmarks (`benches/region_benchmarks.rs`)

Benchmarks for the ptrace region tracking module.

| Benchmark | Description |
|-----------|-------------|
| `TrackedRegion::new` | Region creation overhead |
| `state_transitions/transition_to_executable` | W→X transition |
| `state_transitions/transition_to_writable` | X→W transition |
| `state_transitions/wx_cycle` | Complete W-X cycle |
| `region_checks/contains_hit` | Address lookup (hit) |
| `region_checks/contains_miss` | Address lookup (miss) |
| `region_checks/overlaps_true` | Overlap detection (true) |
| `region_checks/overlaps_false` | Overlap detection (false) |
| `tracker_operations/add` | Adding regions (10, 100, 1000) |
| `tracker_operations/find_hit` | Finding regions (hit) |
| `tracker_operations/find_miss` | Finding regions (miss) |
| `tracker_remove/remove_overlapping` | Removing regions |
| `fault_type/determine_writable` | Fault type for writable region |
| `fault_type/determine_executable` | Fault type for executable region |

### Event Benchmarks (`benches/event_benchmarks.rs`)

Benchmarks for the eBPF event processing module.

| Benchmark | Description |
|-----------|-------------|
| `event_creation/Event::shutdown` | Shutdown event creation |
| `event_creation/Event_with_content` | Event with 4KB content |
| `event_creation/Event_without_content` | Event without content |
| `event_type_checks/is_rwx` | RWX check for each event type |
| `event_type_checks/adds_executable` | Executable check for each type |
| `page_creation/Page::new_empty` | Empty page creation |
| `page_creation/Page::new_with_content` | Page with content |
| `page_creation/Page::new_rwx` | RWX page creation |
| `page_content/clone_content` | Page cloning (4KB, 16KB, 64KB) |
| `page_content/create_content` | Page creation with content |
| `event_batch/create_events` | Batch event creation (10, 100, 1000) |
| `event_batch/filter_rwx_events` | Filtering RWX events from batch |
| `timestamp/SystemTime::now` | System time acquisition |
| `timestamp/timestamp_to_string` | Timestamp formatting |
| `content_patterns/detect_nop_sled` | NOP sled detection |
| `content_patterns/detect_zero_page` | Zero page detection |
| `content_patterns/find_ret_instruction` | RET instruction search |

## Output

Benchmark results are saved to `target/criterion/` and include:

- **HTML Reports**: `target/criterion/report/index.html`
- **Raw Data**: JSON files with statistical analysis
- **Comparison**: Change detection vs previous runs

## Example Output

```
TrackedRegion::new      time:   [24.405 ns 24.500 ns 24.595 ns]

state_transitions/transition_to_executable
                        time:   [12.612 ns 13.773 ns 14.806 ns]

region_checks/contains_hit
                        time:   [794.70 ps 799.42 ps 804.17 ps]

tracker_operations/find_hit/100
                        time:   [45.123 ns 45.678 ns 46.234 ns]
                        thrpt:  [2.1630 Melem/s 2.1893 Melem/s 2.2161 Melem/s]
```

## Interpreting Results

- **time**: [lower bound, estimate, upper bound] at 95% confidence
- **thrpt**: Throughput in elements per second (for batch operations)
- **Change**: Percentage change from previous run (if available)

## Performance Considerations

Based on benchmark results:

1. **Region operations are fast**: Contains/overlaps checks are sub-nanosecond
2. **State transitions**: ~15-20ns per transition, suitable for high-frequency W-X cycles
3. **Tracker scaling**: Linear scaling with number of regions (O(n) lookup)
4. **Memory content**: Cloning 4KB pages takes ~100-200ns

## Adding New Benchmarks

Add benchmarks to existing files or create new benchmark files:

```rust
// In benches/my_benchmarks.rs
use criterion::{criterion_group, criterion_main, Criterion, black_box};

fn my_benchmark(c: &mut Criterion) {
    c.bench_function("my_operation", |b| {
        b.iter(|| {
            black_box(my_operation())
        })
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```

Then add to `Cargo.toml`:

```toml
[[bench]]
name = "my_benchmarks"
harness = false
```

<a href="#top">Back to top</a>