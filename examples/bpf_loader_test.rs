// examples/bpf_loader_test.rs
use emt::BpfTracer;
use std::sync::mpsc::channel;

fn main() -> anyhow::Result<()> {
    // Create a channel to receive memory events
    let (tx, rx) = channel();

    // Get current PID to trace
    let pid = std::process::id() as i32;

    println!("Testing BPF loader with PID: {}", pid);

    // Create BPF tracer
    let mut tracer = BpfTracer::new(tx, pid)?;

    // Start the tracer
    tracer.start()?;

    // Poll for events a few times
    for i in 0..3 {
        println!("Polling events (attempt {})...", i + 1);
        tracer.poll(100)?;

        // Check if we've received any events
        while let Ok(event) = rx.try_recv() {
            println!("Received event: {:?}", event);
        }
    }

    // Stop the tracer
    tracer.stop()?;

    println!("BPF loader test completed successfully");
    Ok(())
}
