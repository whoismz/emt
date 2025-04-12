// examples/bpf_event_test.rs
extern crate libc;
extern crate emt;

use emt::BpfTracer;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::ptr;

fn main() -> anyhow::Result<()> {
    let pid = std::process::id() as i32;
    println!("EMT BPF 事件测试 - PID: {}", pid);
    println!("本程序将验证 BPF 跟踪器是否能正确捕获内存事件");
    
    // 创建通道和跟踪器
    let (tx, rx) = channel();
    let mut tracer = BpfTracer::new(tx, pid)?;
    
    println!("\n1. 启动 BPF 跟踪器");
    match tracer.start() {
        Ok(_) => println!("✓ BPF 跟踪器启动成功"),
        Err(e) => {
            println!("✗ BPF 跟踪器启动失败: {}", e);
            return Err(e);
        }
    }
    
    // 创建一个标志，可以让操作线程停止
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();
    
    // 启动另一个线程执行内存操作
    println!("\n2. 开始执行内存操作");
    let operation_thread = thread::spawn(move || {
        let mut counter = 0;
        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
            counter += 1;
            println!("\n操作 #{}", counter);
            
            // 1. 分配可执行内存
            println!("- 分配可执行内存");
            let size = 4096; // 页大小
            let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            
            let mem = unsafe { libc::mmap(ptr::null_mut(), size, prot, flags, -1, 0) };
            if mem == libc::MAP_FAILED {
                println!("✗ mmap 失败");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            println!("✓ 分配成功，地址: {:p}", mem);
            
            // 写入一些代码
            let code: [u8; 6] = [
                0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
                0xC3                          // ret
            ];
            
            unsafe {
                ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
            }
            
            // 等待以便跟踪器检测到
            thread::sleep(Duration::from_millis(500));
            
            // 2. 修改内存保护
            println!("- 修改内存保护标志 (只读+执行)");
            unsafe {
                libc::mprotect(mem, size, libc::PROT_READ | libc::PROT_EXEC);
            }
            
            // 等待以便跟踪器检测到
            thread::sleep(Duration::from_millis(500));
            
            // 3. 释放内存
            println!("- 释放内存");
            unsafe {
                libc::munmap(mem, size);
            }
            
            // 循环控制
            thread::sleep(Duration::from_millis(500));
            if counter >= 5 {
                println!("内存操作完成 5 次循环");
                break;
            }
        }
    });
    
    // 主线程轮询事件
    println!("\n3. 开始轮询 BPF 事件");
    let mut total_events = 0;
    
    for i in 1..=15 {
        println!("轮询 #{} (等待 1 秒)...", i);
        match tracer.poll(1000) {
            Ok(_) => {},
            Err(e) => println!("轮询错误: {}", e),
        }
        
        // 处理所有接收到的事件
        let mut batch_events = 0;
        while let Ok(event) = rx.try_recv() {
            batch_events += 1;
            total_events += 1;
            println!("事件 #{}: {:?}", total_events, event);
        }
        
        if batch_events > 0 {
            println!("本次轮询收到 {} 个事件", batch_events);
        }
    }
    
    // 停止操作线程和跟踪器
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = operation_thread.join();
    
    println!("\n4. 停止 BPF 跟踪器");
    match tracer.stop() {
        Ok(_) => println!("✓ BPF 跟踪器停止成功"),
        Err(e) => println!("✗ BPF 跟踪器停止失败: {}", e),
    }
    
    // 总结结果
    println!("\n测试结果摘要:");
    println!("总共收到 {} 个内存事件", total_events);
    
    if total_events > 0 {
        println!("✓ BPF 事件捕获正常工作");
    } else {
        println!("✗ BPF 事件捕获失败 - 未收到任何事件");
        println!("可能的原因:");
        println!("  1. 内核版本不支持或缺少所需功能 (要求 Linux 4.15+)");
        println!("  2. 内核安全模块限制了 BPF 功能 (AppArmor/SELinux)");
        println!("  3. BPF 程序没有正确编译或加载");
        println!("  4. perf 缓冲区未正确配置");
    }
    
    Ok(())
}
