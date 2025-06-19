use std::io::{self, BufRead};
use std::process;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    println!("PID: {} Press Enter to start ...", process::id());
    let _ = io::stdin().lock().lines().next();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("Stopping...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    const PAGE_SIZE: usize = 4096;
    let mut cycle_count = 0;

    while running.load(Ordering::SeqCst) {
        if cycle_count >= 5 {
            break;
        }

        cycle_count += 1;
        println!("\nCycle {}", cycle_count);

        // Generate a pseudo-random address for mmap hinting
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as usize;

        let random_addr = ((process::id() as usize) << 12) ^ (cycle_count << 20) ^ nanos;
        let aligned_addr = (random_addr & 0x0000007FFFFF0000) as *mut libc::c_void;

        // Step 1: Allocate memory with read+write permission
        println!("Step 1");
        let memory = unsafe {
            let ptr = libc::mmap(
                aligned_addr,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
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

        // Step 2: Write 4096 bytes to the memory page
        println!("Step 2");
        unsafe {
            let dest = memory as *mut u8;

            // Fill the page with a byte pattern
            for i in 0..PAGE_SIZE {
                *dest.add(i) = ((i + cycle_count) % 256) as u8;
            }

            // Overwrite part of the page with identifiable text
            let text = format!("Cycle {} - PRE-PROTECT", cycle_count);
            let bytes = text.as_bytes();
            let offset = 0;
            let copy_len = bytes.len().min(PAGE_SIZE - offset);
            ptr::copy_nonoverlapping(bytes.as_ptr(), dest.add(offset), copy_len);

            println!("Pre-protect write");
        }

        // Step 3: Change memory protection to read+write+execute
        println!("Step 3");
        unsafe {
            let result = libc::mprotect(
                memory,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );

            if result == 0 {
                println!("Mprotect successful");
            } else {
                eprintln!("Mprotect failed: {}", io::Error::last_os_error());
            }
        }

        // Step 4: Write 4096 bytes again to the now-executable memory
        println!("Step 4");
        unsafe {
            let dest = memory as *mut u8;

            // Fill the page again with a different pattern
            for i in 0..PAGE_SIZE {
                *dest.add(i) = ((i + cycle_count + 128) % 256) as u8;
            }

            // Overwrite part of the page with identifiable post-protect text
            let text = format!("Cycle {} - POST-PROTECT", cycle_count);
            let bytes = text.as_bytes();
            let offset = 0;
            let copy_len = bytes.len().min(PAGE_SIZE - offset);
            ptr::copy_nonoverlapping(bytes.as_ptr(), dest.add(offset), copy_len);

            println!("Post-protect write");
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
