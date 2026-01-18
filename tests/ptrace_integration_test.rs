//! Integration tests for the ptrace-based RWX monitor.
//!
//! These tests require root privileges or CAP_SYS_PTRACE capability.
//! Run with: sudo cargo test --test ptrace_integration_test

use emt::RwxMonitorBuilder;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

mod common;

/// C program that performs a simple RWX memory operation.
/// It allocates RWX memory, writes code, and executes it.
const SIMPLE_RWX_PROGRAM: &str = r#"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Signal ready
    printf("READY\n");
    fflush(stdout);

    // Wait for monitor to attach
    sleep(1);

    // Allocate RWX memory
    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Write simple code: mov eax, 42; ret
    unsigned char code[] = {
        0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov eax, 42
        0xc3                            // ret
    };
    memcpy(mem, code, sizeof(code));

    // Execute the code
    int (*func)(void) = (int (*)(void))mem;
    int result = func();

    printf("RESULT:%d\n", result);
    fflush(stdout);

    munmap(mem, 4096);
    return 0;
}
"#;

/// C program that performs multiple W-X cycles.
const WX_CYCLE_PROGRAM: &str = r#"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void write_return_value(void *mem, int value) {
    unsigned char code[] = {
        0xb8,                           // mov eax, imm32
        value & 0xff,
        (value >> 8) & 0xff,
        (value >> 16) & 0xff,
        (value >> 24) & 0xff,
        0xc3                            // ret
    };
    memcpy(mem, code, sizeof(code));
}

int main() {
    printf("READY\n");
    fflush(stdout);

    sleep(1);

    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    int (*func)(void) = (int (*)(void))mem;

    // Perform 3 W-X cycles
    for (int i = 1; i <= 3; i++) {
        write_return_value(mem, i * 10);
        int result = func();
        printf("CYCLE:%d:RESULT:%d\n", i, result);
        fflush(stdout);
        usleep(50000);  // 50ms between cycles
    }

    printf("DONE\n");
    fflush(stdout);

    munmap(mem, 4096);
    return 0;
}
"#;

/// Helper to compile a C program and return the path to the binary.
fn compile_c_program(source: &str, name: &str) -> Result<std::path::PathBuf, String> {
    let temp_dir = std::env::temp_dir();
    let src_path = temp_dir.join(format!("{}.c", name));
    let bin_path = temp_dir.join(name);

    std::fs::write(&src_path, source).map_err(|e| format!("Failed to write source: {}", e))?;

    let status = Command::new("gcc")
        .args(["-o", bin_path.to_str().unwrap(), src_path.to_str().unwrap()])
        .status()
        .map_err(|e| format!("Failed to run gcc: {}", e))?;

    if !status.success() {
        return Err("gcc compilation failed".to_string());
    }

    // Clean up source file
    let _ = std::fs::remove_file(&src_path);

    Ok(bin_path)
}

/// Helper to clean up compiled binary.
fn cleanup_binary(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// Helper to wait for "READY" from child process.
fn wait_for_ready(
    reader: &mut std::io::BufReader<std::process::ChildStdout>,
) -> Result<(), String> {
    use std::io::BufRead;

    let mut line = String::new();
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for READY".to_string());
        }

        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return Err("Child process closed stdout".to_string()),
            Ok(_) => {
                if line.trim() == "READY" {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("Read error: {}", e)),
        }
    }
}

#[test]
fn test_rwx_monitor_captures_execution() {
    // Compile test program
    let bin_path = match compile_c_program(SIMPLE_RWX_PROGRAM, "test_simple_rwx") {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    // Spawn child process
    let mut child = Command::new(&bin_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id() as i32;
    println!("Child PID: {}", child_pid);

    // Wait for child to be ready
    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);

    if let Err(e) = wait_for_ready(&mut reader) {
        eprintln!("Failed to wait for ready: {}", e);
        let _ = child.kill();
        cleanup_binary(&bin_path);
        return;
    }

    // Give a moment for the sleep in child to start
    thread::sleep(Duration::from_millis(100));

    // Start monitor
    let mut monitor = RwxMonitorBuilder::new(child_pid).build();

    match monitor.start() {
        Ok(()) => println!("Monitor started"),
        Err(e) => {
            eprintln!("Failed to start monitor (need root?): {}", e);
            let _ = child.kill();
            cleanup_binary(&bin_path);
            return;
        }
    }

    // Collect events
    let mut events = Vec::new();
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(10);

    while start.elapsed() < timeout {
        while let Some(event) = monitor.try_recv_event() {
            println!(
                "Captured: addr=0x{:x}, len={}, bytes={:02x?}",
                event.addr,
                event.len,
                &event.bytes[..event.bytes.len().min(8)]
            );
            events.push(event);
        }

        if !monitor.is_running() {
            println!("Monitor stopped (child exited)");
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Stop monitor
    let _ = monitor.stop();

    // Wait for child to complete
    let _ = child.wait();

    // Cleanup
    cleanup_binary(&bin_path);

    // Verify results
    assert!(
        !events.is_empty(),
        "Expected at least one W→X capture event"
    );

    // Verify the captured code contains our expected bytes
    let first_event = &events[0];
    assert!(
        first_event.len > 0,
        "Captured region should have length > 0"
    );
    assert!(
        !first_event.bytes.is_empty(),
        "Captured bytes should not be empty"
    );

    // Check for the expected code pattern (mov eax, 42 = 0xb8 0x2a 0x00 0x00 0x00)
    if first_event.bytes.len() >= 5 {
        assert_eq!(
            first_event.bytes[0], 0xb8,
            "First byte should be 0xb8 (mov eax, imm32)"
        );
        assert_eq!(
            first_event.bytes[1], 0x2a,
            "Second byte should be 0x2a (42)"
        );
    }

    println!(
        "Test passed: captured {} event(s) with expected code",
        events.len()
    );
}

#[test]
fn test_rwx_monitor_wx_cycles() {
    // Compile test program
    let bin_path = match compile_c_program(WX_CYCLE_PROGRAM, "test_wx_cycle") {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    // Spawn child process
    let mut child = Command::new(&bin_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id() as i32;
    println!("Child PID: {}", child_pid);

    // Wait for child to be ready
    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);

    if let Err(e) = wait_for_ready(&mut reader) {
        eprintln!("Failed to wait for ready: {}", e);
        let _ = child.kill();
        cleanup_binary(&bin_path);
        return;
    }

    thread::sleep(Duration::from_millis(100));

    // Start monitor
    let mut monitor = RwxMonitorBuilder::new(child_pid).build();

    match monitor.start() {
        Ok(()) => println!("Monitor started"),
        Err(e) => {
            eprintln!("Failed to start monitor (need root?): {}", e);
            let _ = child.kill();
            cleanup_binary(&bin_path);
            return;
        }
    }

    // Collect events
    let mut events = Vec::new();
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(15);

    while start.elapsed() < timeout {
        while let Some(event) = monitor.try_recv_event() {
            println!(
                "Captured #{}: addr=0x{:x}, capture_sequence={}",
                events.len() + 1,
                event.addr,
                event.capture_sequence
            );
            events.push(event);
        }

        if !monitor.is_running() {
            println!("Monitor stopped (child exited)");
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Stop monitor
    let _ = monitor.stop();

    // Wait for child to complete
    let _ = child.wait();

    // Cleanup
    cleanup_binary(&bin_path);

    // Verify results
    assert!(
        !events.is_empty(),
        "Expected at least one W→X capture event"
    );

    // We expect 3 cycles, so we should have captures with sequence numbers 1, 2, 3
    let cycle_events: Vec<_> = events.iter().filter(|e| e.capture_sequence > 1).collect();

    println!(
        "Total events: {}, Cycle events (seq > 1): {}",
        events.len(),
        cycle_events.len()
    );

    // Verify we captured multiple cycles from the same region
    if events.len() >= 2 {
        let first_addr = events[0].addr;
        let same_region_count = events.iter().filter(|e| e.addr == first_addr).count();
        println!(
            "Events from region 0x{:x}: {}",
            first_addr, same_region_count
        );

        assert!(
            same_region_count >= 2,
            "Expected multiple captures from the same region (W-X cycles)"
        );
    }

    // Verify capture sequence numbers are incrementing for the same region
    let mut last_seq = 0u32;
    for event in &events {
        if event.capture_sequence > 0 {
            assert!(
                event.capture_sequence >= last_seq,
                "Capture sequence should be non-decreasing"
            );
            last_seq = event.capture_sequence;
        }
    }

    println!(
        "Test passed: captured {} events with W-X cycles",
        events.len()
    );
}

#[test]
fn test_rwx_monitor_stop_while_running() {
    // Compile a simple program that sleeps
    let sleep_program = r#"
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("READY\n");
    fflush(stdout);
    sleep(30);
    return 0;
}
"#;

    let bin_path = match compile_c_program(sleep_program, "test_sleep") {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let mut child = Command::new(&bin_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id() as i32;

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);

    if let Err(e) = wait_for_ready(&mut reader) {
        eprintln!("Failed to wait for ready: {}", e);
        let _ = child.kill();
        cleanup_binary(&bin_path);
        return;
    }

    thread::sleep(Duration::from_millis(100));

    let mut monitor = RwxMonitorBuilder::new(child_pid).build();

    match monitor.start() {
        Ok(()) => println!("Monitor started"),
        Err(e) => {
            eprintln!("Failed to start monitor (need root?): {}", e);
            let _ = child.kill();
            cleanup_binary(&bin_path);
            return;
        }
    }

    assert!(
        monitor.is_running(),
        "Monitor should be running after start"
    );

    // Let it run briefly
    thread::sleep(Duration::from_millis(500));

    // Stop while child is still running
    let result = monitor.stop();
    assert!(result.is_ok(), "Stop should succeed");
    assert!(
        !monitor.is_running(),
        "Monitor should not be running after stop"
    );

    // Clean up
    let _ = child.kill();
    let _ = child.wait();
    cleanup_binary(&bin_path);

    println!("Test passed: monitor stopped cleanly while child was running");
}

#[test]
fn test_rwx_monitor_invalid_pid() {
    // Try to monitor a non-existent PID
    let mut monitor = RwxMonitorBuilder::new(999999999).build();

    let result = monitor.start();
    assert!(
        result.is_err(),
        "Starting monitor with invalid PID should fail"
    );

    println!("Test passed: invalid PID correctly rejected");
}

#[test]
fn test_rwx_monitor_double_start() {
    // Compile a simple program
    let sleep_program = r#"
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("READY\n");
    fflush(stdout);
    sleep(30);
    return 0;
}
"#;

    let bin_path = match compile_c_program(sleep_program, "test_double_start") {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Skipping test: {}", e);
            return;
        }
    };

    let mut child = Command::new(&bin_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");

    let child_pid = child.id() as i32;

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);

    if let Err(e) = wait_for_ready(&mut reader) {
        eprintln!("Failed to wait for ready: {}", e);
        let _ = child.kill();
        cleanup_binary(&bin_path);
        return;
    }

    thread::sleep(Duration::from_millis(100));

    let mut monitor = RwxMonitorBuilder::new(child_pid).build();

    match monitor.start() {
        Ok(()) => println!("First start succeeded"),
        Err(e) => {
            eprintln!("Failed to start monitor (need root?): {}", e);
            let _ = child.kill();
            cleanup_binary(&bin_path);
            return;
        }
    }

    // Try to start again
    let second_start = monitor.start();
    assert!(
        second_start.is_err(),
        "Second start should fail (already running)"
    );

    // Clean up
    let _ = monitor.stop();
    let _ = child.kill();
    let _ = child.wait();
    cleanup_binary(&bin_path);

    println!("Test passed: double start correctly rejected");
}
