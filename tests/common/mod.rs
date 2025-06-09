pub fn do_memory_operations() {
    use std::ptr;

    unsafe {
        let _ = libc::mmap(
            ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        
        std::thread::sleep(std::time::Duration::from_secs(1));

        let page = libc::mmap(
            ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if page != libc::MAP_FAILED {
            // Write some data
            ptr::write_bytes(page as *mut u8, 0x90, 5);
            let _ = libc::mprotect(
                page,
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
        }
    }
}
