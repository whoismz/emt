// examples/test_bpf_event.rs
extern crate emt;
extern crate libc;

use emt::BpfTracer;
use std::ptr;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let pid = std::process::id() as i32;
    println!("EMT BPF Event Test - PID: {}", pid);
    println!("This program will verify if the BPF tracer can correctly capture memory events");

    // Create channel and tracer
    let (tx, rx) = channel();
    let mut tracer = BpfTracer::new(tx, pid)?;

    println!("\n1. Starting BPF tracer");
    match tracer.start() {
        Ok(_) => println!("✓ BPF tracer started successfully"),
        Err(e) => {
            println!("✗ BPF tracer failed to start: {}", e);
            return Err(e);
        }
    }

    // Create a flag that allows the operation thread to stop
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    // Start another thread to perform memory operations
    println!("\n2. Starting memory operations");
    let operation_thread = thread::spawn(move || {
        let mut counter = 0;
        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
            counter += 1;
            println!("\nOperation #{}", counter);

            // 1. Allocate executable memory
            println!("- Allocating executable memory");
            let size = 4096; // Page size
            let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

            let mem = unsafe { libc::mmap(ptr::null_mut(), size, prot, flags, -1, 0) };
            if mem == libc::MAP_FAILED {
                println!("✗ mmap failed");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            println!("✓ Allocation successful, address: {:p}", mem);

            // Write some code
            let code: [u8; 6] = [
                0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
                0xC3, // ret
            ];

            unsafe {
                ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
            }

            // Wait for the tracer to detect
            thread::sleep(Duration::from_millis(500));

            // 2. Modify memory protection
            println!("- Modifying memory protection flags (read+execute only)");
            unsafe {
                libc::mprotect(mem, size, libc::PROT_READ | libc::PROT_EXEC);
            }

            // Wait for the tracer to detect
            thread::sleep(Duration::from_millis(500));

            // 3. Free memory
            println!("- Freeing memory");
            unsafe {
                libc::munmap(mem, size);
            }

            // Loop control
            thread::sleep(Duration::from_millis(500));
            if counter >= 5 {
                println!("Memory operations completed 5 cycles");
                break;
            }
        }
    });

    // Main thread polls for events
    println!("\n3. Starting to poll for BPF events");
    let mut total_events = 0;

    for i in 1..=15 {
        println!("Poll #{} (waiting 1 second)...", i);
        match tracer.poll(1000) {
            Ok(_) => {}
            Err(e) => println!("Polling error: {}", e),
        }

        // Process all received events
        let mut batch_events = 0;
        while let Ok(event) = rx.try_recv() {
            batch_events += 1;
            total_events += 1;
            println!("Event #{}: {:?}", total_events, event);
        }

        if batch_events > 0 {
            println!("Received {} events in this poll", batch_events);
        }
    }

    // Stop operation thread and tracer
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = operation_thread.join();

    println!("\n4. Stopping BPF tracer");
    match tracer.stop() {
        Ok(_) => println!("✓ BPF tracer stopped successfully"),
        Err(e) => println!("✗ BPF tracer failed to stop: {}", e),
    }

    // Summarize results
    println!("\nTest Results Summary:");
    println!("Total memory events received: {}", total_events);

    if total_events > 0 {
        println!("✓ BPF event capture is working properly");
    } else {
        println!("✗ BPF event capture failed - no events received");
    }

    Ok(())
}
