use emt::Tracer;
use std::thread;
use std::time::Duration;

mod common;
use common::WRITE_SIZE;
use common::do_memory_operations;

#[test]
fn test_trace_self_memory_operations() {
    // Get current process PID
    let self_pid = std::process::id() as i32;
    println!("Starting self-trace for PID: {}", self_pid);

    let mut tracer = Tracer::new(self_pid);
    if tracer.start().is_err() {
        println!("Failed to start self-tracer");
        return;
    }

    do_memory_operations();

    thread::sleep(Duration::from_secs(1));

    let pages = tracer.stop().unwrap();

    assert_eq!(pages.len(), 5);

    let check = |page_idx: usize, byte_val: u8| {
        let content = pages[page_idx].content.as_ref().unwrap();
        for i in 0..WRITE_SIZE {
            assert_eq!(
                content[i], byte_val,
                "Mismatch at page {page_idx}, offset {i}"
            );
        }
    };

    check(2, 0x90);
    check(3, 0x91);
    check(4, 0xA0);
}
