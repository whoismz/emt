use std::thread;
use std::time::Duration;

fn main() {
    println!("Test target program starting (PID: {})", std::process::id());
    println!("This program will allocate and free executable memory repeatedly.");
    println!("Press Ctrl+C to exit.");

    loop {
        // Allocate executable memory
        let page_size = 4096;
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mem == libc::MAP_FAILED {
            eprintln!("Failed to allocate executable memory");
            break;
        }

        println!("Allocated executable memory at address: {:p}", mem);

        // Write some dummy code to the memory (a simple ret instruction)
        let ret_instruction: u8 = 0xC3; // x86 RET instruction
        unsafe {
            std::ptr::write(mem as *mut u8, ret_instruction);
        }

        // Change permissions to read+execute only
        unsafe {
            libc::mprotect(mem, page_size, libc::PROT_READ | libc::PROT_EXEC);
        }

        // Sleep a bit
        thread::sleep(Duration::from_secs(2));

        // Free the memory
        unsafe {
            libc::munmap(mem, page_size);
        }

        println!("Freed executable memory");

        // Sleep a bit
        thread::sleep(Duration::from_secs(1));
    }
}
