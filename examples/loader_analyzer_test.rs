// examples/integration_test.rs
use emt::{BpfTracer, MemoryAnalyzer};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    // Get current process ID
    let pid = std::process::id() as i32;

    println!("=== Integration Test: BPF Loader + Memory Analyzer ===");

    // Create memory analyzer
    let analyzer = MemoryAnalyzer::new(pid);

    // Get initial executable pages
    let pages = analyzer.get_executable_pages()?;
    println!("Found {} initial executable memory pages", pages.len());

    if !pages.is_empty() {
        let first_page = &pages[0];
        println!(
            "Sample page: Address=0x{:x}, Size={}",
            first_page.address, first_page.size
        );
    }

    // Create BPF tracer
    let (tx, rx) = channel();
    let mut tracer = BpfTracer::new(tx, pid)?;

    // Start the tracer
    tracer.start()?;
    println!("BPF tracer started");

    // Poll for events and check them with the memory analyzer
    for i in 0..3 {
        println!("\nPolling iteration #{}:", i + 1);

        // Poll for events
        tracer.poll(200)?;

        // Process received events
        while let Ok(event) = rx.try_recv() {
            println!("Received event: {:?}", event);

            // Try to get memory page information
            if let Ok(pages) = analyzer.get_executable_pages() {
                // Look for pages related to the event address
                for page in &pages {
                    if page.address <= event.address && page.address + page.size >= event.address {
                        println!(
                            "Found related page: Address=0x{:x}, Size={}",
                            page.address, page.size
                        );

                        if let Some(source) = &page.source_file {
                            println!("Source file: {}", source.display());
                        }

                        break;
                    }
                }
            }
        }
    }

    // Stop the tracer
    tracer.stop()?;
    println!("\nBPF tracer stopped");

    println!("\n=== Integration Test Completed ===");
    Ok(())
}
