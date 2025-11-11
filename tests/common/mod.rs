const PAGE_SIZE: usize = 4096;
pub const WRITE_SIZE: usize = 4096;

pub fn do_memory_operations() {
    use std::ptr;

    unsafe {
        let addr = libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE * 3,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if addr != libc::MAP_FAILED {
            {
                let first_page = addr as *mut u8;
                ptr::write_bytes(first_page, 0x90, WRITE_SIZE);
            }

            {
                let second_page = (addr as *mut u8).add(PAGE_SIZE);
                ptr::write_bytes(second_page, 0x91, WRITE_SIZE);
            }

            {
                let third_page = (addr as *mut u8).add(PAGE_SIZE * 2);
                ptr::write_bytes(third_page, 0xA0, WRITE_SIZE);
            }

            let _ = libc::mprotect(
                addr,
                PAGE_SIZE * 3, // three pages
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
        }
    }
}
