// examples/detailed_bpf_test.rs
use emt::BpfTracer;
use emt::EventType;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    // Create a channel to receive memory events
    let (tx, rx) = channel();

    // Get current process ID
    let pid = std::process::id() as i32;

    println!("=== BPF Loader Detailed Test ===");
    println!("Target PID: {}", pid);

    // Create BPF tracer
    let mut tracer = BpfTracer::new(tx, pid)?;

    // Test 1: Initial state verification
    println!("\nTest 1: Verify initial state");
    // BPF tracer should initially be in stopped state

    // Test 2: Start the tracer
    println!("\nTest 2: Start tracer");
    tracer.start()?;
    println!("Tracer started");

    // Test 3: Receive events
    println!("\nTest 3: Receive events");
    println!("Waiting to receive 3 events...");

    let mut events_received = 0;
    let start_time = std::time::Instant::now();

    while events_received < 3 && start_time.elapsed() < Duration::from_secs(5) {
        tracer.poll(100)?;

        while let Ok(event) = rx.try_recv() {
            events_received += 1;
            println!("Received event #{}: {:?}", events_received, event);
            println!("  - Type: {:?}", event.event_type);
            println!("  - Address: 0x{:x}", event.address);
            println!("  - Size: {} bytes", event.size);
            println!("  - PID: {}", event.pid);
        }
    }

    println!("Total events received: {}", events_received);

    // Test 4: Stop the tracer
    println!("\nTest 4: Stop tracer");
    tracer.stop()?;
    println!("Tracer stopped");

    // Test 5: Verify no more events after stopping
    println!("\nTest 5: Verify no events after stopping");
    tracer.poll(500)?;

    let additional_events = rx.try_iter().count();
    println!(
        "Received {} events after stopping (should be 0)",
        additional_events
    );

    println!("\n=== Test Completed ===");
    Ok(())
}
