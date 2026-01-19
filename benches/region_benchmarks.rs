//! Benchmarks for the ptrace region tracking module.
//!
//! Run with: cargo bench --bench region_benchmarks

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use emt::{RegionTracker, TrackedRegion};

/// Benchmark TrackedRegion creation.
fn bench_region_creation(c: &mut Criterion) {
    c.bench_function("TrackedRegion::new", |b| {
        b.iter(|| {
            TrackedRegion::new(
                black_box(0x7f0000000000),
                black_box(0x1000),
                black_box(0x7), // RWX
                black_box(emt::ptrace::RegionSource::Mmap),
            )
        })
    });
}

/// Benchmark state transitions.
fn bench_state_transitions(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_transitions");

    group.bench_function("transition_to_executable", |b| {
        b.iter_batched(
            || TrackedRegion::new(0x7f0000000000, 0x1000, 0x7, emt::ptrace::RegionSource::Mmap),
            |mut region| {
                black_box(region.transition_to_executable());
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("transition_to_writable", |b| {
        b.iter_batched(
            || {
                let mut region = TrackedRegion::new(
                    0x7f0000000000,
                    0x1000,
                    0x7,
                    emt::ptrace::RegionSource::Mmap,
                );
                region.transition_to_executable();
                region
            },
            |mut region| {
                black_box(region.transition_to_writable());
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("wx_cycle", |b| {
        b.iter_batched(
            || TrackedRegion::new(0x7f0000000000, 0x1000, 0x7, emt::ptrace::RegionSource::Mmap),
            |mut region| {
                region.transition_to_executable();
                region.transition_to_writable();
                black_box(&region);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark region contains/overlaps checks.
fn bench_region_checks(c: &mut Criterion) {
    let region = TrackedRegion::new(
        0x7f0000000000,
        0x10000, // 64KB
        0x7,
        emt::ptrace::RegionSource::Mmap,
    );

    let mut group = c.benchmark_group("region_checks");

    group.bench_function("contains_hit", |b| {
        b.iter(|| black_box(region.contains(black_box(0x7f0000008000))))
    });

    group.bench_function("contains_miss", |b| {
        b.iter(|| black_box(region.contains(black_box(0x7f0000020000))))
    });

    group.bench_function("overlaps_true", |b| {
        b.iter(|| black_box(region.overlaps(black_box(0x7f0000005000), black_box(0x2000))))
    });

    group.bench_function("overlaps_false", |b| {
        b.iter(|| black_box(region.overlaps(black_box(0x7f0000020000), black_box(0x1000))))
    });

    group.finish();
}

/// Benchmark RegionTracker with varying number of regions.
fn bench_tracker_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracker_operations");

    for size in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        // Benchmark adding regions
        group.bench_with_input(BenchmarkId::new("add", size), size, |b, &size| {
            b.iter_batched(
                || RegionTracker::new(),
                |mut tracker| {
                    for i in 0..size {
                        let addr = 0x7f0000000000 + (i as u64 * 0x10000);
                        tracker.add(TrackedRegion::new(
                            addr,
                            0x1000,
                            0x7,
                            emt::ptrace::RegionSource::Mmap,
                        ));
                    }
                    black_box(tracker)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        // Benchmark finding regions (hit)
        group.bench_with_input(BenchmarkId::new("find_hit", size), size, |b, &size| {
            let mut tracker = RegionTracker::new();
            for i in 0..size {
                let addr = 0x7f0000000000 + (i as u64 * 0x10000);
                tracker.add(TrackedRegion::new(
                    addr,
                    0x1000,
                    0x7,
                    emt::ptrace::RegionSource::Mmap,
                ));
            }
            // Search for middle region
            let search_addr = 0x7f0000000000 + ((size / 2) as u64 * 0x10000) + 0x500;

            b.iter(|| black_box(tracker.find(black_box(search_addr))))
        });

        // Benchmark finding regions (miss)
        group.bench_with_input(BenchmarkId::new("find_miss", size), size, |b, &size| {
            let mut tracker = RegionTracker::new();
            for i in 0..size {
                let addr = 0x7f0000000000 + (i as u64 * 0x10000);
                tracker.add(TrackedRegion::new(
                    addr,
                    0x1000,
                    0x7,
                    emt::ptrace::RegionSource::Mmap,
                ));
            }
            // Search for address not in any region
            let search_addr = 0x1000;

            b.iter(|| black_box(tracker.find(black_box(search_addr))))
        });
    }

    group.finish();
}

/// Benchmark tracker remove operations.
fn bench_tracker_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracker_remove");

    for size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("remove_overlapping", size),
            size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut tracker = RegionTracker::new();
                        for i in 0..size {
                            let addr = 0x7f0000000000 + (i as u64 * 0x10000);
                            tracker.add(TrackedRegion::new(
                                addr,
                                0x1000,
                                0x7,
                                emt::ptrace::RegionSource::Mmap,
                            ));
                        }
                        tracker
                    },
                    |mut tracker| {
                        // Remove middle region
                        let addr = 0x7f0000000000 + ((size / 2) as u64 * 0x10000);
                        tracker.remove_overlapping(addr, 0x1000);
                        black_box(tracker)
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

/// Benchmark determine_fault_type.
fn bench_fault_type_determination(c: &mut Criterion) {
    let mut group = c.benchmark_group("fault_type");

    group.bench_function("determine_writable", |b| {
        let region =
            TrackedRegion::new(0x7f0000000000, 0x1000, 0x7, emt::ptrace::RegionSource::Mmap);
        b.iter(|| black_box(region.determine_fault_type()))
    });

    group.bench_function("determine_executable", |b| {
        let mut region =
            TrackedRegion::new(0x7f0000000000, 0x1000, 0x7, emt::ptrace::RegionSource::Mmap);
        region.transition_to_executable();
        b.iter(|| black_box(region.determine_fault_type()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_region_creation,
    bench_state_transitions,
    bench_region_checks,
    bench_tracker_operations,
    bench_tracker_remove,
    bench_fault_type_determination,
);

criterion_main!(benches);
