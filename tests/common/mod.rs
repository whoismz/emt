const PAGE_SIZE: usize = 4096;

pub fn do_memory_operations() {
    use std::ptr;

    unsafe {
        let _ = libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE * 2, // two pages
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        std::thread::sleep(std::time::Duration::from_secs(1));

        let page = libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE * 3, // three pages
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if page != libc::MAP_FAILED {
            // writes first page
            ptr::write_bytes(page as *mut u8, 0x90, 5);

            // writes second page
            let second_page = (page as *mut u8).add(4096);
            ptr::write_bytes(second_page as *mut u8, 0x91, 5);

            let _ = libc::mprotect(
                page,
                PAGE_SIZE * 3, // three pages
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
        }
    }
}
