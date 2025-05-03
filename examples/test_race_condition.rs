use std::io::{self, BufRead};
use std::process;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

    fn mprotect(addr: *mut libc::c_void, len: libc::size_t, prot: libc::c_int) -> libc::c_int;

    fn munmap(addr: *mut libc::c_void, len: libc::size_t) -> libc::c_int;
}

fn main() {
    println!("[RACE CONDITION TEST]");
    println!("[INFO] PID: {}", process::id());
    println!("[INFO] Press Enter to start");

    let _ = io::stdin().lock().lines().next();

    println!("[INFO] Starting the test");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Test 1
    println!("\n[TEST 1] Rapid allocation and deallocation");
    for _i in 0..100 {
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let mem = unsafe {
            mmap(
                ptr::null_mut(),
                4096,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        unsafe {
            munmap(mem, 4096);
        }
    }
    println!("[TEST 1] Ending");
}
