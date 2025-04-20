extern crate emt;
extern crate libc;

use emt::BpfTracer;
use std::ptr;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let pid = std::process::id() as i32;
    println!("[PID] {}", pid);

    let (tx, rx) = channel();
    let mut tracer = BpfTracer::new(tx, pid)?;

    if tracer.start().is_err() {
        println!("[ERR] Failed to start tracer");
        return Ok(());
    }

    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    let operation_thread = thread::spawn(move || {
        for cycle in 1..=5 {
            println!("\n[Cycle] {} --------------------", cycle);

            let size = 4096;
            let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            let mem = unsafe { libc::mmap(ptr::null_mut(), size, prot, flags, -1, 0) };

            if mem == libc::MAP_FAILED {
                println!("[WARN] mmap failed");
                continue;
            }

            let code: [u8; 6] = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
            unsafe {
                ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
                libc::mprotect(mem, size, libc::PROT_READ | libc::PROT_EXEC);
                libc::munmap(mem, size);
            }

            thread::sleep(Duration::from_millis(500));
        }

        running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
    });

    let mut total_events = 0;

    for _ in 0..15 {
        tracer.poll(2000).ok();

        while let Ok(event) = rx.try_recv() {
            total_events += 1;
            println!("[Event] {:?}", event);
        }

        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
    }

    let _ = operation_thread.join();
    tracer.stop().ok();

    println!("\n[Done] {} event(s) received\n", total_events);
    Ok(())
}
