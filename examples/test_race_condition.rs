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

// 形式化权限标志为可读字符串
fn format_prot(prot: libc::c_int) -> String {
    let mut result = String::new();

    if prot & libc::PROT_READ != 0 {
        result.push('R');
    } else {
        result.push('-');
    }
    if prot & libc::PROT_WRITE != 0 {
        result.push('W');
    } else {
        result.push('-');
    }
    if prot & libc::PROT_EXEC != 0 {
        result.push('X');
    } else {
        result.push('-');
    }

    result
}

fn main() {
    println!("[RACE CONDITION TEST]");
    println!("[INFO] PID: {}", process::id());
    println!("[INFO] Press Enter to start");

    let _ = io::stdin().lock().lines().next();

    println!("[INFO] Starting the test");

    // 创建一个标志来控制线程
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // 启动统计线程
    let stats_thread = thread::spawn(move || {
        let mut total_ops = 0;
        let start_time = std::time::Instant::now();

        while r.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(1));
            let elapsed = start_time.elapsed().as_secs();
            if elapsed > 0 {
                println!(
                    "[STATS] Operations: {}, Rate: {}/sec",
                    total_ops,
                    total_ops / elapsed
                );
            }
            total_ops += 1;
        }
    });

    // Test 1
    println!("\n[TEST 1] Rapid allocation and deallocation");
    for i in 0..100 {
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let mem = unsafe {
            mmap(
                std::ptr::null_mut(),
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

    /*
    // 测试2: 快速权限切换
    println!("\n[TEST 2] Rapid permission changes");
    let mem2 = unsafe {
        mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    println!("[TEST 2] Allocated memory at {:p}", mem2);

    for i in 0..200 {
        // 在RW和RWX之间快速切换
        let prot = if i % 2 == 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        };

        unsafe {
            mprotect(mem2, 4096, prot);
        }

        // 每50次打印一次进度
        if i % 50 == 0 {
            println!("[TEST 2] Completed {} permission changes", i);
        }

        // 这个超短暂的延迟是为了让内核有时间执行其他任务
        thread::sleep(Duration::from_micros(10));
    }

    unsafe {
        munmap(mem2, 4096);
    }

    // 测试3: 多线程并发操作
    println!("\n[TEST 3] Multi-threaded concurrent operations");
    let thread_count = 4;
    let ops_per_thread = 50;

    let mut handles = vec![];

    for t in 0..thread_count {
        let handle = thread::spawn(move || {
            for i in 0..ops_per_thread {
                // 分配内存
                let mem = unsafe {
                    mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };

                // 修改权限为可执行
                unsafe {
                    mprotect(
                        mem,
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    );
                }

                // 非常短暂的延迟
                thread::sleep(Duration::from_micros(5));

                // 释放内存
                unsafe {
                    munmap(mem, 4096);
                }

                // 每10次打印一次进度
                if i % 10 == 0 {
                    println!("[TEST 3] Thread {} completed {} iterations", t, i);
                }
            }
        });

        handles.push(handle);
    }

    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }

    // 测试4: 快速分配->修改权限->释放序列
    println!("\n[TEST 4] Rapid allocate->change->free sequence");

    for i in 0..100 {
        // 步骤1: 分配RW内存
        let mem4 = unsafe {
            mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        // 步骤2: 修改为RWX
        unsafe {
            mprotect(
                mem4,
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
        }

        // 步骤3: 立即释放
        unsafe {
            munmap(mem4, 4096);
        }

        // 每20次打印一次进度
        if i % 20 == 0 {
            println!("[TEST 4] Completed {} sequences", i);
        }

        // 微小的延迟
        thread::sleep(Duration::from_micros(50));
    }

    // 停止统计线程
    running.store(false, Ordering::SeqCst);
    let _ = stats_thread.join();

    println!("\n[INFO] Race condition tests completed!");
    println!("[INFO] Check your memory tracer logs to see if any events were missed.");
    */
}
