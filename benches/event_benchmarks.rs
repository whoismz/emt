//! Benchmarks for the eBPF event processing module.
//!
//! Run with: cargo bench --bench event_benchmarks

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use emt::{Event, EventType, Page};
use std::time::SystemTime;

/// Benchmark Event creation.
fn bench_event_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_creation");

    group.bench_function("Event::shutdown", |b| {
        b.iter(|| black_box(Event::shutdown()))
    });

    group.bench_function("Event_with_content", |b| {
        let content = vec![0x90u8; 4096];
        b.iter(|| {
            black_box(Event {
                event_type: EventType::Map,
                addr: 0x7f0000000000,
                size: 4096,
                timestamp: SystemTime::now(),
                timestamp_str: String::from("2024-01-01 00:00:00"),
                pid: 1234,
                content: Some(content.clone()),
                prot: Some(0x7),
            })
        })
    });

    group.bench_function("Event_without_content", |b| {
        b.iter(|| {
            black_box(Event {
                event_type: EventType::Map,
                addr: 0x7f0000000000,
                size: 4096,
                timestamp: SystemTime::now(),
                timestamp_str: String::from("2024-01-01 00:00:00"),
                pid: 1234,
                content: None,
                prot: Some(0x5),
            })
        })
    });

    group.finish();
}

/// Benchmark EventType checks.
fn bench_event_type_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_type_checks");

    let event_types = [
        ("Map", EventType::Map),
        ("RwxMap", EventType::RwxMap),
        ("Mprotect", EventType::Mprotect),
        ("RwxMprotect", EventType::RwxMprotect),
        ("Unmap", EventType::Unmap),
        ("Shutdown", EventType::Shutdown),
    ];

    for (name, event_type) in event_types.iter() {
        group.bench_with_input(BenchmarkId::new("is_rwx", name), event_type, |b, et| {
            b.iter(|| black_box(et.is_rwx()))
        });

        group.bench_with_input(
            BenchmarkId::new("adds_executable", name),
            event_type,
            |b, et| b.iter(|| black_box(et.adds_executable())),
        );
    }

    group.finish();
}

/// Benchmark Page creation.
fn bench_page_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("page_creation");

    group.bench_function("Page::new_empty", |b| {
        b.iter(|| {
            black_box(Page::new(
                0x7f0000000000,
                4096,
                String::from("2024-01-01 00:00:00"),
                None,
            ))
        })
    });

    group.bench_function("Page::new_with_content", |b| {
        let content = vec![0x90u8; 4096];
        b.iter(|| {
            let mut page = Page::new(
                0x7f0000000000,
                4096,
                String::from("2024-01-01 00:00:00"),
                None,
            );
            page.content = Some(content.clone());
            black_box(page)
        })
    });

    group.bench_function("Page::new_rwx", |b| {
        let content = vec![0x90u8; 4096];
        b.iter(|| {
            let mut page = Page::new_rwx(
                0x7f0000000000,
                4096,
                String::from("2024-01-01 00:00:00"),
                None,
            );
            page.content = Some(content.clone());
            black_box(page)
        })
    });

    group.finish();
}

/// Benchmark page content operations.
fn bench_page_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("page_content");

    for size in [4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("clone_content", size), size, |b, &size| {
            let content = vec![0x90u8; size];
            let mut page = Page::new(
                0x7f0000000000,
                size,
                String::from("2024-01-01 00:00:00"),
                None,
            );
            page.content = Some(content);

            b.iter(|| black_box(page.clone()))
        });

        group.bench_with_input(
            BenchmarkId::new("create_content", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let content = vec![0x90u8; size];
                    let mut page = Page::new(
                        0x7f0000000000,
                        size,
                        String::from("2024-01-01 00:00:00"),
                        None,
                    );
                    page.content = Some(content);
                    black_box(page)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark event batch processing simulation.
fn bench_event_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_batch");

    for batch_size in [10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("create_events", batch_size),
            batch_size,
            |b, &batch_size| {
                b.iter(|| {
                    let events: Vec<Event> = (0..batch_size)
                        .map(|i| Event {
                            event_type: if i % 2 == 0 {
                                EventType::Map
                            } else {
                                EventType::Mprotect
                            },
                            addr: 0x7f0000000000 + (i as usize * 0x1000),
                            size: 4096,
                            timestamp: SystemTime::now(),
                            timestamp_str: String::from("2024-01-01 00:00:00"),
                            pid: 1234,
                            content: None,
                            prot: Some(0x5),
                        })
                        .collect();
                    black_box(events)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("filter_rwx_events", batch_size),
            batch_size,
            |b, &batch_size| {
                let events: Vec<Event> = (0..batch_size)
                    .map(|i| Event {
                        event_type: if i % 3 == 0 {
                            EventType::RwxMap
                        } else if i % 3 == 1 {
                            EventType::Map
                        } else {
                            EventType::Mprotect
                        },
                        addr: 0x7f0000000000 + (i as usize * 0x1000),
                        size: 4096,
                        timestamp: SystemTime::now(),
                        timestamp_str: String::from("2024-01-01 00:00:00"),
                        pid: 1234,
                        content: None,
                        prot: Some(0x7),
                    })
                    .collect();

                b.iter(|| {
                    let rwx_events: Vec<_> =
                        events.iter().filter(|e| e.event_type.is_rwx()).collect();
                    black_box(rwx_events)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark timestamp operations.
fn bench_timestamp(c: &mut Criterion) {
    let mut group = c.benchmark_group("timestamp");

    group.bench_function("SystemTime::now", |b| {
        b.iter(|| black_box(SystemTime::now()))
    });

    group.bench_function("timestamp_to_string", |b| {
        b.iter(|| {
            let now = SystemTime::now();
            let datetime: chrono::DateTime<chrono::Utc> = now.into();
            black_box(datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        })
    });

    group.finish();
}

/// Benchmark memory content patterns.
fn bench_content_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_patterns");

    group.bench_function("detect_nop_sled", |b| {
        let content = vec![0x90u8; 4096]; // NOP sled
        b.iter(|| {
            let nop_count = content.iter().filter(|&&b| b == 0x90).count();
            black_box(nop_count)
        })
    });

    group.bench_function("detect_zero_page", |b| {
        let content = vec![0x00u8; 4096];
        b.iter(|| {
            let is_zero = content.iter().all(|&b| b == 0);
            black_box(is_zero)
        })
    });

    group.bench_function("find_ret_instruction", |b| {
        let mut content = vec![0x90u8; 4096];
        content[100] = 0xc3; // ret instruction
        b.iter(|| {
            let ret_pos = content.iter().position(|&b| b == 0xc3);
            black_box(ret_pos)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_event_creation,
    bench_event_type_checks,
    bench_page_creation,
    bench_page_content,
    bench_event_batch,
    bench_timestamp,
    bench_content_patterns,
);

criterion_main!(benches);
