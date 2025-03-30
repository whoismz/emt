use emt::trace_process;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    // Create output directory
    let output_dir = PathBuf::from("./trace_output");

    // Get current process PID to trace
    let pid = std::process::id() as i32;

    println!("=== Memory Tracer Test ===");
    println!("Starting memory tracer for PID: {}", pid);
    println!("Output directory: {}", output_dir.display());

    // Generate some test memory activity
    // (Allocate and use executable memory during the test)
    thread::spawn(|| {
        for i in 0..10 {
            println!("Test thread iteration: {}", i);

            // Allocate some memory to be traced
            let page_size = 4096;
            let mem = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    page_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };

            if mem == libc::MAP_FAILED {
                eprintln!("Failed to allocate executable memory");
                continue;
            }

            println!("Allocated executable memory at address: {:p}", mem);

            // Sleep a bit to allow the tracer to detect it
            thread::sleep(Duration::from_millis(500));

            // Free the memory
            unsafe {
                libc::munmap(mem, page_size);
            }

            thread::sleep(Duration::from_millis(500));
        }
    });

    // Start memory tracer (set save_content=false for now)
    let tracer = trace_process(pid, &output_dir, false)?;

    // Let it run for a while
    println!("Tracer running... (press Ctrl+C to stop)");

    // Set up Ctrl+C handler
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;

    // Wait for Ctrl+C or timeout (30 seconds)
    let timeout = Duration::from_secs(30);
    if rx.recv_timeout(timeout).is_ok() {
        println!("Received Ctrl+C, stopping tracer");
    } else {
        println!("Reached timeout, stopping tracer");
    }

    // Tracer will be automatically stopped when dropped

    println!("Check output directory for logs: {}", output_dir.display());
    println!("=== Test completed ===");

    Ok(())
}
