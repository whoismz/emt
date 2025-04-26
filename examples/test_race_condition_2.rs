use std::io::{self, BufRead};
use std::process;
use std::ptr;
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
    println!("[INFO] Press Enter to start");

    let _ = io::stdin().lock().lines().next();

    // 分配一个可读可写可执行的内存页
    let size = 4096;
    let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    println!("[INFO] Allocating RWX memory of size {} bytes", size);

    let mem = unsafe { mmap(std::ptr::null_mut(), size, prot, flags, -1, 0) };

    if mem == libc::MAP_FAILED {
        println!("[ERROR] Memory allocation failed!");
        return;
    }

    println!("[INFO] Memory allocated at address: {:p}", mem);
    println!("[INFO] Starting to modify memory content...");
    println!("[INFO] Press Ctrl+C to stop");

    // mov al, <value>; ret
    let mut code_template: [u8; 3] = [0xB0, 0x00, 0xC3];

    unsafe {
        ptr::copy_nonoverlapping(code_template.as_ptr(), mem as *mut u8, code_template.len());
    }

    println!("[INFO] Initial code written: [0xB0, 0x00, 0xC3] (mov al, 0; ret)");

    let mut counter = 1;
    loop {
        let value = counter % 256;

        unsafe {
            let byte_ptr = (mem as *mut u8).add(1);
            *byte_ptr = value as u8;
        }

        println!(
            "[MODIFY] Iteration {}: Changed operand to {} (0x{:02X})",
            counter, value, value
        );
        println!(
            "[MODIFY] Current code: [0xB0, 0x{:02X}, 0xC3] (mov al, {}; ret)",
            value, value
        );

        // 验证我们可以执行这个代码
        if counter % 10 == 0 {
            // 创建一个函数指针并调用它
            type FnType = unsafe extern "C" fn() -> u8;
            let func = unsafe { std::mem::transmute::<*mut libc::c_void, FnType>(mem) };

            let result = unsafe { func() };

            println!(
                "[VERIFY] Function call returned: {} (expected {})",
                result, value
            );

            if result != value as u8 {
                println!("[ERROR] Memory execution verification failed!");
            }
        }

        counter += 1;

        // 暂停一会儿，使测试更容易观察
        thread::sleep(Duration::from_secs(1));
    }

    // 这段代码永远不会执行，因为上面是无限循环
    // 但为了完整性，保留清理代码
    unsafe {
        munmap(mem, size);
    }
}
