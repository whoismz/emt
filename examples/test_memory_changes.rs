use std::io::{self, BufRead};
use std::process;
use std::ptr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    fn mprotect(addr: *mut libc::c_void, len: libc::size_t, prot: libc::c_int) -> libc::c_int;
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

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as usize;

        let random_addr = ((process::id() as usize) << 12) ^ (cycle_count << 20) ^ nanos;
        let aligned_addr = (random_addr & 0x0000007FFFFF0000) as *mut libc::c_void;

        let size = 2048 + cycle_count * 100;
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let exec_mem = unsafe { mmap(aligned_addr, size, prot, flags, -1, 0) };

        println!("aligned_addr = {:p}", aligned_addr);
        println!("exec_mem = {:p}", exec_mem);
        
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

        println!("[INFO] Changing memory protection to READ | EXECUTE (drop WRITE)");
        let new_prot = libc::PROT_READ | libc::PROT_EXEC;
        let ret = unsafe { mprotect(exec_mem, size, new_prot) };
        if ret != 0 {
            eprintln!(
                "[ERROR] mprotect failed with errno {}",
                io::Error::last_os_error()
            );
            unsafe {
                munmap(exec_mem, size);
            }
            break;
        }

        thread::sleep(Duration::from_secs(2));

        println!("[INFO] Freeing memory at {:p}", exec_mem);
        unsafe {
            munmap(exec_mem, size);
        }

        println!("[INFO] Cycle complete. Sleeping 2s before next iteration...");
        thread::sleep(Duration::from_secs(2));
    }
}
