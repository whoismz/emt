use std::io::{self, BufRead};
use std::process;
use std::ptr;
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== Memory Data Capture Test ===");
    println!("Current PID: {}", process::id());
    println!("Start your memory tracer with this PID, then press Enter to begin test...");
    
    let _ = io::stdin().lock().lines().next();

    println!("\n[Step 1] Allocating memory with RW permissions...");
    
    const PAGE_SIZE: usize = 4096;
    const TEST_PATTERN_SIZE: usize = 128;

    let memory = unsafe {
        let ptr = libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0
        );

        if ptr == libc::MAP_FAILED {
            panic!("Failed to allocate memory: {}", io::Error::last_os_error());
        }

        println!("Memory allocated at address: {:p}", ptr);
        ptr
    };
    
    thread::sleep(Duration::from_secs(1));

    println!("\n[Step 2] Writing test pattern to memory...");
    
    unsafe {
        let dest = memory as *mut u8;
        
        for i in 0..64 {
            *dest.add(i) = i as u8;
        }
        
        let text = b"This is a test pattern for memory tracing. ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.";
        ptr::copy_nonoverlapping(text.as_ptr(), dest.add(64), text.len());

        println!("Wrote test pattern (total {} bytes):", TEST_PATTERN_SIZE);
        println!("- Bytes 0-63: Incrementing sequence (0-63)");
        println!("- Bytes 64-{}: ASCII text", 64 + text.len() - 1);
    }
    
    thread::sleep(Duration::from_secs(1));

    println!("\n[Step 3] Changing memory permissions to RX (read + execute)...");
    
    unsafe {
        let result = libc::mprotect(
            memory,
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_EXEC  // 改为读执行权限
        );

        if result != 0 {
            panic!("Failed to change memory permissions: {}", io::Error::last_os_error());
        }

        println!("Memory permissions changed to read+execute");
    }
    
    thread::sleep(Duration::from_secs(2));

    println!("\n[Step 4] Freeing memory...");
    
    unsafe {
        libc::munmap(memory, PAGE_SIZE);
        println!("Memory freed");
    }
    
    thread::sleep(Duration::from_secs(1));
}