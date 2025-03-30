use emt::ExecutablePage;
use std::time::SystemTime;

fn main() {
    // Create a sample executable page
    let page = ExecutablePage {
        address: 0x7fff00000000,
        size: 4096,
        timestamp: SystemTime::now(),
        source_file: Some(std::path::PathBuf::from("/bin/bash")),
        content: None,
        protection_flags: 0x5, // PROT_READ | PROT_EXEC
    };

    println!("Created sample page: {:?}", page);

    // Test system time functionality
    let time_now = SystemTime::now();
    println!("Current time: {:?}", time_now);

    println!("Models test completed successfully");
}
