//! Test for X->W->X->W... circular permission pattern support.
//!
//! This example tests the ptrace approach's ability to capture multiple
//! execution events from the same memory region when permissions cycle
//! between executable and writable.

use emt::RwxMonitorBuilder;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    println!("=== RWX Cycle Test (X->W->X->W...) ===\n");

    // Compile test program
    let temp_dir = std::env::temp_dir();
    let src_path = temp_dir.join("rwx_cycle_test.c");
    let bin_path = temp_dir.join("rwx_cycle_test");

    std::fs::write(&src_path, CYCLE_TEST_PROGRAM)?;

    let status = Command::new("gcc")
        .args(["-o", bin_path.to_str().unwrap(), src_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        return Err("Failed to compile test program".into());
    }

    // Spawn test process (paused, waiting for us to attach)
    let child = Command::new(&bin_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_pid = child.id() as i32;
    println!("Target PID: {}", child_pid);

    // Give the process time to start and reach the sleep
    thread::sleep(Duration::from_millis(500));

    // Start monitor
    let mut monitor = RwxMonitorBuilder::new(child_pid).build();

    monitor.start()?;
    println!("Monitor attached, waiting for cycle events...\n");

    // Collect events
    let start = std::time::Instant::now();
    let mut events = Vec::new();
    let timeout = Duration::from_secs(15);

    while start.elapsed() < timeout {
        while let Some(event) = monitor.try_recv_event() {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!(
                "📍 Capture #{}: addr=0x{:x}, len={} bytes",
                event.capture_sequence, event.addr, event.len
            );
            println!("   Fault addr: 0x{:x}", event.fault_addr);
            println!("   RIP: 0x{:x}", event.registers.rip);

            // Show first 16 bytes of captured code
            let preview_len = event.bytes.len().min(16);
            print!("   Code bytes: ");
            for b in &event.bytes[..preview_len] {
                print!("{:02x} ", b);
            }
            if event.bytes.len() > 16 {
                print!("...");
            }
            println!();

            events.push(event);
        }

        if !monitor.is_running() {
            println!("\nMonitor stopped (target process exited)");
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Stop the monitor - don't extend from result.exec_events since we already
    // collected events via try_recv_event() to avoid duplicates
    let result = monitor.stop()?;
    let _ = result;

    // Cleanup
    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&bin_path);

    // Report results
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                        RESULTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let total_events = events.len();
    let cycle_events = events.iter().filter(|e| e.capture_sequence > 1).count();

    println!("Total captures: {}", total_events);
    println!("First captures: {}", total_events - cycle_events);
    println!("Cycle captures: {}", cycle_events);

    // Group events by region address
    let mut regions: std::collections::HashMap<u64, Vec<_>> = std::collections::HashMap::new();
    for event in &events {
        regions.entry(event.addr).or_default().push(event);
    }

    println!("\nPer-region breakdown:");
    for (addr, region_events) in &regions {
        println!("  Region 0x{:x}: {} capture(s)", addr, region_events.len());
        for event in region_events {
            println!("    - Capture #{}", event.capture_sequence);
        }
    }

    // Verify test success
    println!();
    if total_events == 0 {
        println!("❌ FAILED: No events captured");
        std::process::exit(1);
    } else if cycle_events == 0 {
        println!("⚠️  PARTIAL: Events captured but no cycle events detected");
        println!("   (Expected multiple captures from same region)");
        std::process::exit(1);
    } else {
        println!(
            "✅ SUCCESS: Captured {} total events with {} from X->W->X cycles",
            total_events, cycle_events
        );
    }

    Ok(())
}

/// Test program that performs X->W->X->W... cycles on the same memory region.
/// It creates RWX memory, writes code, executes it, then changes back to RW,
/// writes new code, and executes again - repeating this cycle multiple times.
const CYCLE_TEST_PROGRAM: &str = r#"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

// Simple x86_64 function that returns a value in EAX
// mov eax, <value>; ret
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
    printf("RWX Cycle Test Program\n");
    printf("PID: %d\n", getpid());
    fflush(stdout);

    // Wait for monitor to attach
    sleep(2);

    // Allocate memory with RWX permissions
    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Memory allocated at %p\n", mem);
    fflush(stdout);

    int (*func)(void) = (int (*)(void))mem;
    int num_cycles = 3;

    for (int cycle = 1; cycle <= num_cycles; cycle++) {
        printf("\n=== Cycle %d ===\n", cycle);
        fflush(stdout);

        // Write code that returns the cycle number * 10
        int expected_value = cycle * 10;
        write_return_value(mem, expected_value);

        printf("Wrote code to return %d\n", expected_value);
        printf("Code bytes: ");
        unsigned char *code = (unsigned char *)mem;
        for (int i = 0; i < 6; i++) {
            printf("%02x ", code[i]);
        }
        printf("\n");
        fflush(stdout);

        // Execute the code (this triggers W->X capture)
        printf("Executing...\n");
        fflush(stdout);

        int result = func();

        printf("Result: %d (expected %d) - %s\n",
               result, expected_value,
               result == expected_value ? "OK" : "MISMATCH");
        fflush(stdout);

        if (cycle < num_cycles) {
            // Change permissions back to RW for next cycle (X->W transition)
            printf("Changing to RW for next cycle...\n");
            fflush(stdout);

            if (mprotect(mem, 4096, PROT_READ | PROT_WRITE) != 0) {
                perror("mprotect RW failed");
                munmap(mem, 4096);
                return 1;
            }

            // Small delay to make the cycle more visible in logs
            usleep(100000);

            // Change back to RWX to write and execute again
            printf("Changing to RWX...\n");
            fflush(stdout);

            if (mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                perror("mprotect RWX failed");
                munmap(mem, 4096);
                return 1;
            }
        }
    }

    printf("\n=== Test Complete ===\n");
    printf("Performed %d write-execute cycles\n", num_cycles);
    fflush(stdout);

    munmap(mem, 4096);
    return 0;
}
"#;
