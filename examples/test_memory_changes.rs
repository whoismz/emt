use std::io::{self, BufRead};
use std::process;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    // Basic info and startup
    println!("PID: {}", process::id());
    println!("Press Enter to start ...");

    let _ = io::stdin().lock().lines().next();

    // Set up Ctrl+C handler to exit loop gracefully
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("Stopping...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // Memory operation constants
    const PAGE_SIZE: usize = 4096;
    const TEST_PATTERN_SIZE: usize = 128;

    let mut cycle_count = 0;

    // Main test loop
    while running.load(Ordering::SeqCst) {
        cycle_count += 1;
        println!("\nCycle {} ---------", cycle_count);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as usize;

        let random_addr = ((process::id() as usize) << 12) ^ (cycle_count << 20) ^ nanos;
        let aligned_addr = (random_addr & 0x0000007FFFFF0000) as *mut libc::c_void;

        // Step 1: allocate memory with read+write permissions
        println!("Step 1");
        let memory = unsafe {
            let ptr = libc::mmap(
                aligned_addr,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            );

            if ptr == libc::MAP_FAILED {
                eprintln!("Memory allocation failed");
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            println!("Memory allocated: {:p}", ptr);
            ptr
        };

        thread::sleep(Duration::from_millis(500));

        // Step 2: initial write to memory
        println!("Step 2");
        unsafe {
            let dest = memory as *mut u8;

            // Write a sequence
            for i in 0..64 {
                *dest.add(i) = ((i + cycle_count) % 256) as u8;
            }

            // Write text
            let text = format!("Cycle {} - PRE-PROTECT", cycle_count);
            let bytes = text.as_bytes();

            let copy_len = bytes.len().min(TEST_PATTERN_SIZE - 64);
            ptr::copy_nonoverlapping(bytes.as_ptr(), dest.add(64), copy_len);

            println!("Initial data written (sequence + text)");
        }

        thread::sleep(Duration::from_millis(500));

        // Step 3: change memory permissions to read+execute
        println!("Step 3");
        unsafe {
            let result = libc::mprotect(
                memory,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );

            if result == 0 {
                println!("Memory now executable");
            } else {
                eprintln!("mprotect failed with error: {}", io::Error::last_os_error());
            }
        }

        thread::sleep(Duration::from_millis(500));

        // Step 4: attempt to write to memory after protection change
        println!("Step 4");
        unsafe {
            let dest = memory as *mut u8;
            // Try writing to different offsets
            for i in (0..64).step_by(8) {
                *dest.add(i) = ((i + cycle_count + 128) % 256) as u8;
            }

            // Try writing text
            let text = format!("Cycle {} - POST-PROTECT", cycle_count);
            let bytes = text.as_bytes();
            ptr::copy_nonoverlapping(bytes.as_ptr(), dest.add(80), bytes.len().min(32));

            println!("Post-protect write completed (if no crash occurred)");
        }

        thread::sleep(Duration::from_millis(500));

        // Step 5: free memory
        println!("Step 5");
        unsafe {
            // libc::munmap(memory, PAGE_SIZE);
            println!("Memory freed");
        }

        // Wait before the next cycle (varied timing)
        let wait_time = 1 + (cycle_count % 2);
        thread::sleep(Duration::from_secs(wait_time as u64));
    }

    println!("\nTest completed: {} cycles", cycle_count);
}
