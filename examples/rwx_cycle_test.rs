//! Test for true W-X cycle support.
//!
//! This example tests the ptrace approach's ability to handle
//! the W-X cycle via SIGSEGV signals.
//!
//! 1. mmap(RWX) → Monitor gives RW only
//! 2. Write code → Allowed (region is RW)
//! 3. Execute → SIGSEGV → Monitor captures memory, switches to RX
//! 4. Write again → SIGSEGV → Monitor switches to RW
//! 5. Execute → SIGSEGV → Monitor captures memory, switches to RX
//! ...

use emt::RwxMonitorBuilder;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    println!("=== True W-X Cycle Test ===\n");

    // Compile test program
    let temp_dir = std::env::temp_dir();
    let src_path = temp_dir.join("wx_cycle_test.c");
    let bin_path = temp_dir.join("wx_cycle_test");

    std::fs::write(&src_path, WX_CYCLE_TEST_PROGRAM)?;

    let status = Command::new("gcc")
        .args(["-o", bin_path.to_str().unwrap(), src_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        return Err("Failed to compile test program".into());
    }

    // Spawn test process
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
    println!("Monitor attached, waiting for W-X cycle events...\n");

    // Collect events
    let start = std::time::Instant::now();
    let mut events = Vec::new();
    let timeout = Duration::from_secs(20);

    while start.elapsed() < timeout {
        while let Some(event) = monitor.try_recv_event() {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!(
                "📍 W→X Capture #{}: addr=0x{:x}, len={} bytes",
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

            // Decode the simple return value from the code
            if event.bytes.len() >= 5 && event.bytes[0] == 0xb8 {
                let value = u32::from_le_bytes([
                    event.bytes[1],
                    event.bytes[2],
                    event.bytes[3],
                    event.bytes[4],
                ]);
                println!("   Decoded: mov eax, {} (0x{:x})", value, value);
            }

            if event.capture_sequence > 1 {
                println!("   ✓ This is from a W-X cycle!");
            }

            events.push(event);
        }

        if !monitor.is_running() {
            println!("\nMonitor stopped (target process exited)");
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Stop the monitor
    let _ = monitor.stop()?;

    // Cleanup
    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&bin_path);

    // Report results
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("                        RESULTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let total_events = events.len();
    let cycle_events = events.iter().filter(|e| e.capture_sequence > 1).count();

    println!("Total W→X captures: {}", total_events);
    println!("First capture: {}", if total_events > 0 { 1 } else { 0 });
    println!("Cycle captures (capture #2+): {}", cycle_events);

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
        println!("   (Expected multiple captures from same region via W-X cycle)");
        std::process::exit(1);
    } else {
        println!(
            "✅ SUCCESS: Captured {} total events with {} from W-X cycles",
            total_events, cycle_events
        );
        println!("\nThe W-X cycle is working correctly:");
        println!("  - Execution attempts trigger memory capture (W→X)");
        println!("  - Write attempts trigger permission switch (X→W)");
        println!("  - No mprotect calls needed from the target!");
    }

    Ok(())
}

/// Test program that performs W-X cycles WITHOUT calling mprotect.
/// The monitor handles all permission transitions via SIGSEGV.
///
/// Flow:
/// 1. mmap(RWX) - monitor gives us RW
/// 2. write code - works (RW)
/// 3. execute - SIGSEGV, monitor captures & gives RX
/// 4. write code - SIGSEGV, monitor gives RW
/// 5. execute - SIGSEGV, monitor captures & gives RX
/// ... and so on
const WX_CYCLE_TEST_PROGRAM: &str = r#"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

// Simple x86_64 function: mov eax, <value>; ret
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
    printf("W<->X Cycle Test Program (no mprotect calls)\n");
    printf("PID: %d\n", getpid());
    fflush(stdout);

    // Wait for monitor to attach
    sleep(2);

    // Allocate memory with RWX permissions
    // Note: Monitor will strip EXEC, giving us RW only
    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Memory allocated at %p\n", mem);
    printf("We requested RWX, but monitor gives us RW.\n");
    printf("All W<->X transitions happen via SIGSEGV!\n\n");
    fflush(stdout);

    int (*func)(void) = (int (*)(void))mem;
    int num_cycles = 3;

    for (int cycle = 1; cycle <= num_cycles; cycle++) {
        printf("=== Cycle %d ===\n", cycle);
        fflush(stdout);

        // Write code - if region is RX, this triggers SIGSEGV -> monitor switches to RW
        int expected_value = cycle * 10;
        printf("Writing code (value=%d)...\n", expected_value);
        fflush(stdout);

        write_return_value(mem, expected_value);

        printf("Write succeeded. Code bytes: ");
        unsigned char *code = (unsigned char *)mem;
        for (int i = 0; i < 6; i++) {
            printf("%02x ", code[i]);
        }
        printf("\n");
        fflush(stdout);

        // Execute - if region is RW, this triggers SIGSEGV -> monitor captures & switches to RX
        printf("Executing...\n");
        fflush(stdout);

        int result = func();

        printf("Result: %d (expected %d) - %s\n\n",
               result, expected_value,
               result == expected_value ? "OK" : "MISMATCH");
        fflush(stdout);

        // Small delay between cycles
        usleep(100000);
    }

    printf("=== Test Complete ===\n");
    printf("Performed %d W<->X cycles without any mprotect calls!\n", num_cycles);
    printf("All transitions were handled by the monitor via SIGSEGV.\n");
    fflush(stdout);

    munmap(mem, 4096);
    return 0;
}
"#;
