//! Minimal RWX monitor self-test.

use emt::RwxMonitorBuilder;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("=== RWX Monitor Self-Test ===\n");

    // Compile test program
    let temp_dir = std::env::temp_dir();
    let src_path = temp_dir.join("rwx_test.c");
    let bin_path = temp_dir.join("rwx_test");

    std::fs::write(&src_path, TEST_PROGRAM)?;

    let status = Command::new("gcc")
        .args(["-o", bin_path.to_str().unwrap(), src_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        return Err("Failed to compile test program".into());
    }

    // Spawn test process
    let child = Command::new(&bin_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let child_pid = child.id() as i32;
    println!("Target PID: {}", child_pid);

    thread::sleep(Duration::from_millis(500));

    // Start monitor
    let mut monitor = RwxMonitorBuilder::new(child_pid).build();

    monitor.start()?;
    println!("Monitor attached\n");

    // Collect events
    let start = std::time::Instant::now();
    let mut events = Vec::new();

    while start.elapsed() < Duration::from_secs(10) {
        while let Some(event) = monitor.try_recv_event() {
            println!("Captured: 0x{:x} ({} bytes)", event.addr, event.len);
            println!(
                "  First bytes: {:02x?}",
                &event.bytes[..event.bytes.len().min(8)]
            );
            events.push(event);
        }

        if !monitor.is_running() {
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let result = monitor.stop()?;
    // Don't extend from result.exec_events - we already collected via try_recv_event()
    // to avoid duplicates. result.exec_events contains the same events.
    let _ = result;

    // Cleanup
    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&bin_path);

    // Report
    println!("\n=== Result ===");
    if events.is_empty() {
        println!("FAILED: No events captured");
        std::process::exit(1);
    } else {
        println!("SUCCESS: {} event(s) captured", events.len());
    }

    Ok(())
}

const TEST_PROGRAM: &str = r#"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    sleep(2);

    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 1;

    unsigned char code[] = { 0xb8, 0x1a, 0x00, 0x00, 0x00, 0xc3 };
    memcpy(mem, code, sizeof(code));

    int (*func)(void) = mem;
    int result = func();

    munmap(mem, 4096);
    return result == 42 ? 0 : 1;
}
"#;
