// examples/test_bpf_events.rs
use anyhow::Result;
use emt::BpfTracer;
use std::sync::mpsc::channel;
use std::time::Duration;

fn main() -> Result<()> {
    println!("BPF Event Test - Testing raw event capturing");

    // 1. 创建通道接收事件
    let (tx, rx) = channel();

    // 2. 监控当前进程
    let pid = std::process::id() as i32;
    println!("Monitoring current process (PID: {})", pid);

    // 3. 创建BPF跟踪器并启动
    let mut tracer = BpfTracer::new(tx, pid)?;
    println!("Starting BPF tracer...");
    if let Err(e) = tracer.start() {
        eprintln!("Failed to start BPF tracer: {}", e);
        return Err(e.into());
    }
    println!("BPF tracer started successfully");

    // 4. 创建测试线程，执行会触发mmap的操作
    println!("Starting test thread to generate mmap events...");
    std::thread::spawn(move || {
        for i in 1..=5 {
            println!("\nTest iteration #{}", i);

            // 执行mmap操作
            unsafe {
                println!("Executing mmap...");
                let addr = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );

                if addr == libc::MAP_FAILED {
                    eprintln!("mmap failed: {}", std::io::Error::last_os_error());
                } else {
                    println!("mmap succeeded at address: {:p}", addr);

                    // 等待一会儿让事件被捕获
                    std::thread::sleep(Duration::from_millis(500));

                    // 执行munmap
                    println!("Executing munmap...");
                    libc::munmap(addr, 4096);
                }
            }

            std::thread::sleep(Duration::from_secs(1));
        }
    });

    // 5. 主线程接收和显示事件
    println!("\nWaiting for events (15 seconds)...");
    let mut total_events = 0;

    for i in 1..=15 {
        println!("Poll #{}", i);

        match tracer.poll(1000) {
            Ok(_) => {}
            Err(e) => eprintln!("Poll error: {}", e),
        }

        // 检查是否有事件被接收
        let mut events_this_poll = 0;
        while let Ok(event) = rx.try_recv() {
            events_this_poll += 1;
            total_events += 1;
            println!("Event received: {:?}", event);
        }

        if events_this_poll > 0 {
            println!("Received {} events in this poll", events_this_poll);
        }
    }

    println!("\nTest complete. Total events captured: {}", total_events);
    if total_events > 0 {
        println!("✅ SUCCESS: BPF event capture is working!");
    } else {
        println!("❌ FAILURE: No events were captured!");
    }

    // 6. 停止跟踪器
    println!("Stopping tracer...");
    tracer.stop()?;

    Ok(())
}
