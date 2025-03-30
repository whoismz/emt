// examples/self_modifying_code.rs
use std::thread;
use std::time::Duration;

type JitFunction = fn() -> i32;

fn main() {
    println!("Self-modifying code test (PID: {})", std::process::id());
    println!("This program will create and execute dynamically generated code.");

    // Infinite loop (until Ctrl+C)
    loop {
        // 1. Allocate executable memory
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

        // 2. Write initial function - returns 42
        // Simple x86-64 function that returns 42
        // mov eax, 42
        // ret
        let function_code: &[u8] = &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3];

        unsafe {
            std::ptr::copy_nonoverlapping(
                function_code.as_ptr(),
                mem as *mut u8,
                function_code.len(),
            );
        }

        // 3. Execute the function
        let func = unsafe { std::mem::transmute::<*mut libc::c_void, JitFunction>(mem) };
        let result = func();
        println!("First execution result: {}", result);

        // Sleep a bit to let the tracer detect the memory
        thread::sleep(Duration::from_secs(2));

        // 4. Modify the function - now returns 100
        // mov eax, 100
        // ret
        let modified_code: &[u8] = &[0xb8, 0x64, 0x00, 0x00, 0x00, 0xc3];

        unsafe {
            std::ptr::copy_nonoverlapping(
                modified_code.as_ptr(),
                mem as *mut u8,
                modified_code.len(),
            );
        }

        // 5. Execute the modified function
        let result = func();
        println!("After modification result: {}", result);

        // Sleep a bit
        thread::sleep(Duration::from_secs(2));

        // 6. Free the memory
        unsafe {
            libc::munmap(mem, page_size);
        }

        println!("Freed executable memory");

        // Wait a bit before next iteration
        thread::sleep(Duration::from_secs(1));
    }
}
