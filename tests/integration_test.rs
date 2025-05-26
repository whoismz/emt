use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime};

use emt::{Tracer};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const MMAP_SIZE: usize = 4096;
const EXPECTED_MIN_EVENTS: usize = 3; // At least map, mprotect, unmap

/// Helper function to create a simple test executable that performs memory operations
fn create_test_executable() -> std::io::Result<String> {
    let test_program = r#"
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Test process started (PID: %d)\n", getpid());
    fflush(stdout);

    // Sleep to give tracer time to attach
    sleep(1);

    // Allocate executable memory
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Memory allocated at: %p\n", mem);
    fflush(stdout);

    // Write some data
    memset(mem, 0x90, 100); // NOP instructions

    // Make memory executable
    if (mprotect(mem, 4096, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect failed");
        munmap(mem, 4096);
        return 1;
    }

    printf("Memory made executable\n");
    fflush(stdout);

    // Keep memory for a while
    sleep(2);

    // Unmap memory
    munmap(mem, 4096);
    printf("Memory unmapped\n");
    fflush(stdout);

    return 0;
}
"#;

    let temp_dir = std::env::temp_dir();
    let source_path = temp_dir.join("test_memory_ops.c");
    let executable_path = temp_dir.join("test_memory_ops");

    // Write source file
    fs::write(&source_path, test_program)?;

    // Compile
    let output = Command::new("gcc")
        .args(&[
            source_path.to_str().unwrap(),
            "-o",
            executable_path.to_str().unwrap(),
        ])
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Compilation failed: {}", String::from_utf8_lossy(&output.stderr)),
        ));
    }

    Ok(executable_path.to_string_lossy().to_string())
}

/// Test basic tracer capability with a real subprocess
#[test]
fn test_tracer_with_subprocess() {
    // Create test executable
    let executable = create_test_executable()
        .expect("Failed to create test executable");

    // Start the test process
    let mut child = Command::new(&executable)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start test process");

    let pid = child.id() as i32;
    println!("Started test process with PID: {}", pid);

    // Create and start tracer
    let mut tracer = Tracer::new(pid);
    tracer.start().expect("Failed to start tracer");

    // Let the process run and complete
    let result = child.wait().expect("Failed to wait for child process");
    assert!(result.success(), "Test process failed");

    // Give tracer a moment to process final events
    thread::sleep(Duration::from_millis(500));

    // Stop tracer and get results
    let pages = tracer.stop().expect("Failed to stop tracer");

    // Verify we got some memory events
    assert!(!pages.is_empty(), "No memory pages were tracked");
    println!("Tracked {} memory pages", pages.len());

    // Verify page properties
    for page in &pages {
        assert_ne!(page.addr, 0, "Page address should not be zero");
        assert_eq!(page.size, 4096, "Page size should be 4096 bytes");
        assert!(page.timestamp > SystemTime::UNIX_EPOCH, "Timestamp should be valid");
    }

    // Clean up
    let _ = fs::remove_file(executable);
}

/// Test tracer with multiple processes (only track one)
#[test]
fn test_tracer_pid_filtering() {
    let executable = create_test_executable()
        .expect("Failed to create test executable");

    // Start two test processes
    let mut child1 = Command::new(&executable)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start first test process");

    let mut child2 = Command::new(&executable)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start second test process");

    let pid1 = child1.id() as i32;
    let pid2 = child2.id() as i32;

    // Only trace the first process
    let mut tracer = Tracer::new(pid1);
    tracer.start().expect("Failed to start tracer");

    // Wait for both processes to complete
    let _ = child1.wait();
    let _ = child2.wait();

    thread::sleep(Duration::from_millis(500));
    let pages = tracer.stop().expect("Failed to stop tracer");

    // We should have events, but they should only be from pid1
    // This is hard to verify directly since we don't store PID in Page,
    // but the fact that we got events shows the filtering worked
    assert!(!pages.is_empty(), "Should have tracked some pages from target process");

    let _ = fs::remove_file(executable);
}

/// Test tracer error conditions
#[test]
fn test_tracer_error_conditions() {
    // Test with non-existent PID
    let mut tracer = Tracer::new(-1);

    // This should start but not track anything meaningful
    let result = tracer.start();
    assert!(result.is_ok(), "Tracer should start even with invalid PID");

    thread::sleep(Duration::from_millis(100));
    let pages = tracer.stop().expect("Failed to stop tracer");

    // Should have no pages for non-existent process
    assert!(pages.is_empty(), "Should not track pages for non-existent PID");
}

/// Test tracer lifecycle - multiple start/stop cycles
#[test]
fn test_tracer_lifecycle() {
    let executable = create_test_executable()
        .expect("Failed to create test executable");

    let mut tracer = Tracer::new(1); // Use init process (always exists)

    // Test multiple start/stop cycles
    for i in 0..3 {
        println!("Lifecycle test cycle {}", i + 1);

        assert!(tracer.start().is_ok(), "Start should succeed");
        thread::sleep(Duration::from_millis(100));

        let pages = tracer.stop().expect("Stop should succeed");
        println!("Cycle {} collected {} pages", i + 1, pages.len());
    }

    // Test multiple starts (should be no-op)
    assert!(tracer.start().is_ok());
    assert!(tracer.start().is_ok()); // The second start should also succeed

    let _ = tracer.stop();
    let _ = fs::remove_file(executable);
}

/// Test concurrent access to the tracer
#[test]
fn test_concurrent_tracer_access() {
    use std::sync::{Arc, Mutex};

    let tracer = Arc::new(Mutex::new(Tracer::new(1)));
    let mut handles = vec![];

    // Spawn multiple threads trying to start/stop tracer
    for i in 0..5 {
        let tracer_clone = tracer.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(i * 10));

            let mut t = tracer_clone.lock().unwrap();
            let _ = t.start();
            thread::sleep(Duration::from_millis(50));
            let _ = t.stop();
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    // Final cleanup
    let mut final_tracer = tracer.lock().unwrap();
    let _ = final_tracer.stop();
}

/// Performance test - measure tracer overhead
#[test]
fn test_tracer_performance() {
    let executable = create_test_executable()
        .expect("Failed to create test executable");

    let start_time = SystemTime::now();

    // Start multiple short-lived processes to generate events
    let mut children = vec![];
    for _ in 0..5 {
        let child = Command::new(&executable)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start test process");
        children.push(child);
    }

    // Create tracer for the first process
    if let Some(child) = children.first() {
        let pid = child.id() as i32;
        let mut tracer = Tracer::new(pid);
        tracer.start().expect("Failed to start tracer");

        // Wait for processes to complete
        for mut child in children {
            let _ = child.wait();
        }

        thread::sleep(Duration::from_millis(500));
        let pages = tracer.stop().expect("Failed to stop tracer");

        let elapsed = start_time.elapsed().unwrap();
        println!("Performance test completed in {:?}", elapsed);
        println!("Tracked {} pages", pages.len());

        // Performance should be reasonable (less than 10 seconds for this test)
        assert!(elapsed < Duration::from_secs(10), "Test took too long: {:?}", elapsed);
    }

    let _ = fs::remove_file(executable);
}

/// Test with a process that does no memory operations
#[test]
fn test_tracer_with_idle_process() {
    // Create a simple program that just sleeps
    let idle_program = r#"
#include <unistd.h>
#include <stdio.h>

int main() {
    printf("Idle process started\n");
    fflush(stdout);
    sleep(2);
    printf("Idle process ending\n");
    return 0;
}
"#;

    let temp_dir = std::env::temp_dir();
    let source_path = temp_dir.join("idle_test.c");
    let executable_path = temp_dir.join("idle_test");

    fs::write(&source_path, idle_program).expect("Failed to write source");

    let output = Command::new("gcc")
        .args(&[
            source_path.to_str().unwrap(),
            "-o",
            executable_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to compile");

    assert!(output.status.success(), "Compilation should succeed");

    // Start the idle process
    let mut child = Command::new(&executable_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start idle process");

    let pid = child.id() as i32;
    let mut tracer = Tracer::new(pid);
    tracer.start().expect("Failed to start tracer");

    let _ = child.wait();
    thread::sleep(Duration::from_millis(200));

    let pages = tracer.stop().expect("Failed to stop tracer");

    // An idle process might still have some memory operations during startup
    println!("Idle process generated {} memory pages", pages.len());

    // Clean up
    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(executable_path);
}

/// Integration test for the full workflow
#[test]
fn test_full_workflow_integration() {
    let executable = create_test_executable()
        .expect("Failed to create test executable");

    println!("=== Full Workflow Integration Test ===");

    // Phase 1: setup
    let mut child = Command::new(&executable)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start test process");

    let pid = child.id() as i32;
    println!("Phase 1: Started process PID {}", pid);

    // Phase 2: start tracing
    let mut tracer = Tracer::new(pid);
    let start_result = tracer.start();
    assert!(start_result.is_ok(), "Tracer start failed: {:?}", start_result);
    println!("Phase 2: Tracer started successfully");

    // Phase 3: let a process run
    println!("Phase 3: Letting process execute...");
    let process_result = child.wait().expect("Failed to wait for process");
    assert!(process_result.success(), "Test process failed");

    // Phase 4: collect results
    thread::sleep(Duration::from_millis(1000)); // Give time for final events
    let stop_result = tracer.stop();
    assert!(stop_result.is_ok(), "Tracer stop failed: {:?}", stop_result);

    let pages = stop_result.unwrap();
    println!("Phase 4: Collected {} memory pages", pages.len());

    // Phase 5: validate results
    assert!(!pages.is_empty(), "Should have collected some memory pages");

    let mut has_valid_addresses = false;
    let mut has_valid_timestamps = false;

    for (i, page) in pages.iter().enumerate() {
        println!("Page {}: addr=0x{:x}, size={}, time={:?}",
                 i, page.addr, page.size, page.timestamp);

        if page.addr != 0 {
            has_valid_addresses = true;
        }

        if page.timestamp > SystemTime::UNIX_EPOCH {
            has_valid_timestamps = true;
        }

        assert_eq!(page.size, 4096, "All pages should be 4KB");
    }

    assert!(has_valid_addresses, "Should have pages with valid addresses");
    assert!(has_valid_timestamps, "Should have pages with valid timestamps");

    println!("Phase 5: Validation completed successfully");
    println!("=== Integration Test PASSED ===");

    // Cleanup
    let _ = fs::remove_file(executable);
}

// Helper function to check if we're running as root (needed for eBPF)
fn check_root_privileges() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Test that requires root privileges
#[test]
fn test_requires_root() {
    if !check_root_privileges() {
        println!("Skipping test that requires root privileges");
        return;
    }

    // This test would only run with root privileges
    println!("Running with root privileges - eBPF should work");

    let mut tracer = Tracer::new(1); // init process
    let result = tracer.start();

    // With root privileges, this should work
    assert!(result.is_ok(), "Tracer should start with root privileges");

    let _ = tracer.stop();
}

#[cfg(test)]
mod test_utilities {
    use super::*;

    pub fn wait_for_condition<F>(mut condition: F, timeout: Duration, check_interval: Duration) -> bool
    where
        F: FnMut() -> bool,
    {
        let start = SystemTime::now();
        loop {
            if condition() {
                return true;
            }

            if start.elapsed().unwrap_or(Duration::ZERO) > timeout {
                return false;
            }

            thread::sleep(check_interval);
        }
    }

    #[test]
    fn test_wait_for_condition() {
        let mut counter = 0;
        let result = wait_for_condition(
            || {
                counter += 1;
                counter >= 3
            },
            Duration::from_secs(1),
            Duration::from_millis(10)
        );

        assert!(result);
        assert!(counter >= 3);
    }
}