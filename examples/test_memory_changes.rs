use std::io::{self, BufRead};
use std::process;
use std::ptr;
use std::slice;
use std::thread;
use std::time::Duration;

unsafe extern "C" {
    fn mmap(
        addr: *mut libc::c_void,
        len: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> *mut libc::c_void;

    fn munmap(addr: *mut libc::c_void, len: libc::size_t) -> libc::c_int;
}

fn main() {
    println!("[INFO] PID: {}", process::id());
    println!("[INFO] Start the memory monitor now using this PID.");
    println!("[INFO] Press Enter to begin memory operations...");

    let _ = io::stdin().lock().lines().next();

    println!("[INFO] Starting memory mutation loop...");

    let mut cycle_count = 0;
    loop {
        cycle_count += 1;
        println!("\n[INFO] === Cycle #{} ===", cycle_count);

        // x86_64: mov eax, 42; ret; nop; nop
        let initial_code: [u8; 8] = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];

        let size = 4096;
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let exec_mem = unsafe { mmap(ptr::null_mut(), size, prot, flags, -1, 0) };

        if exec_mem == libc::MAP_FAILED {
            eprintln!("[WARN] mmap failed, retrying...");
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        println!("[INFO] Allocated memory at: {:p}", exec_mem);

        unsafe {
            ptr::copy_nonoverlapping(
                initial_code.as_ptr(),
                exec_mem as *mut u8,
                initial_code.len(),
            );
        }

        println!("[INFO] Written initial code: {:02X?}", &initial_code);
        thread::sleep(Duration::from_secs(2));

        for i in 1..=3 {
            let new_val = 0x2A + i * 10;
            println!(
                "[INFO] Modifying return value: mov eax, {} (0x{:X})",
                new_val, new_val
            );

            unsafe {
                let mem_slice = slice::from_raw_parts_mut(exec_mem as *mut u8, size);
                mem_slice[1] = new_val as u8;
                println!("[INFO] Current code bytes: {:02X?}", &mem_slice[..8]);
            }

            thread::sleep(Duration::from_secs(2));
        }

        println!("[INFO] Freeing memory at {:p}", exec_mem);
        unsafe {
            munmap(exec_mem, size);
        }

        println!("[INFO] Cycle complete. Sleeping 2s before next iteration...");
        thread::sleep(Duration::from_secs(2));
    }
}
