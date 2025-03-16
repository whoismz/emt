// test_memory_changes.rs
use std::ptr;
use std::slice;
use std::thread;
use std::time::Duration;
use std::process;

// Required for memory allocation with executable permissions
unsafe extern "C" {
    fn mmap(addr: *mut libc::c_void, len: libc::size_t, prot: libc::c_int,
            flags: libc::c_int, fd: libc::c_int, offset: libc::off_t) -> *mut libc::c_void;
    fn munmap(addr: *mut libc::c_void, len: libc::size_t) -> libc::c_int;
}

fn main() {
    println!("Process ID: {}", process::id());
    println!("Start the memory monitor now with this PID.");
    println!("Waiting 5 seconds before starting memory operations...");
    println!("This program will run continuously until manually terminated (Ctrl+C).");
    thread::sleep(Duration::from_secs(5));

    let mut cycle_count = 0;
    
    loop {
        cycle_count += 1;
        println!("\n[TEST] Starting cycle #{}", cycle_count);
        
        // Define a simple machine code function (x86_64)
        let initial_code: [u8; 8] = [
            0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 42
            0xC3,                          // ret
            0x90, 0x90                     // nop, nop (padding)
        ];

        // Allocate executable memory
        let size = 4096; // Page size
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        
        let exec_mem = unsafe {
            mmap(ptr::null_mut(), size, prot, flags, -1, 0)
        };
        
        if exec_mem == libc::MAP_FAILED {
            eprintln!("mmap failed!");
            thread::sleep(Duration::from_secs(1));
            continue;
        }
        
        println!("[TEST] Allocated executable memory at: {:p}", exec_mem);
        
        // Copy initial code to the executable memory
        unsafe {
            ptr::copy_nonoverlapping(initial_code.as_ptr(), exec_mem as *mut u8, initial_code.len());
        }
        
        // Sleep to allow the monitor to detect the new region
        println!("[TEST] Executable memory initialized, sleeping for 2 seconds...");
        thread::sleep(Duration::from_secs(2));
        
        // Modify the code multiple times
        for i in 1..4 {
            println!("[TEST] Modifying executable memory (change #{})...", i);
            unsafe {
                let mem_slice = slice::from_raw_parts_mut(exec_mem as *mut u8, size);
                // Change the return value
                mem_slice[1] = (0x2A + i * 10) as u8; // 42 -> 52 -> 62 -> 72
            }
            
            // Sleep to allow the monitor to detect the change
            println!("[TEST] Memory modified, sleeping for 2 seconds...");
            thread::sleep(Duration::from_secs(2));
        }
        
        // Free the memory
        println!("[TEST] Freeing executable memory...");
        unsafe {
            munmap(exec_mem, size);
        }
        
        // Sleep before starting next cycle
        println!("[TEST] Cycle completed, sleeping for 2 seconds before next cycle...");
        thread::sleep(Duration::from_secs(2));
    }
}
