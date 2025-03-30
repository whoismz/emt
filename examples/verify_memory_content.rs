// examples/verify_memory_content.rs
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get trace output directory from command line or use default
    let args: Vec<String> = std::env::args().collect();
    let trace_dir = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("./trace_output")
    };

    println!("Verifying memory content in: {}", trace_dir.display());

    // Find all memory dump files
    let entries = fs::read_dir(&trace_dir)?;
    let mut memory_files = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();
            if filename.starts_with("mem_") && filename.ends_with(".bin") {
                memory_files.push(path);
            }
        }
    }

    println!("Found {} memory dump files", memory_files.len());

    // Check each memory file
    for (idx, file_path) in memory_files.iter().enumerate() {
        let content = fs::read(file_path)?;
        println!("\nMemory file #{}: {}", idx + 1, file_path.display());
        println!("Size: {} bytes", content.len());

        // Check for executable code patterns
        if content.len() >= 6 {
            // Look for function patterns we used
            let found_42 = check_for_pattern(&content, &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]);
            let found_100 = check_for_pattern(&content, &[0xb8, 0x64, 0x00, 0x00, 0x00, 0xc3]);

            if found_42 {
                println!("FOUND: Function that returns 42");
            }

            if found_100 {
                println!("FOUND: Function that returns 100");
            }

            if !found_42 && !found_100 {
                println!("No known function patterns found");

                // Print first 32 bytes for inspection
                println!("First 32 bytes:");
                print_hex_dump(&content, 32);
            }
        } else {
            println!("Content too small to be a valid function");
        }
    }

    println!("\nMemory content verification completed");
    Ok(())
}

// Check if a memory dump contains a specific byte pattern
fn check_for_pattern(content: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > content.len() {
        return false;
    }

    for i in 0..=(content.len() - pattern.len()) {
        let mut match_found = true;
        for j in 0..pattern.len() {
            if content[i + j] != pattern[j] {
                match_found = false;
                break;
            }
        }

        if match_found {
            return true;
        }
    }

    false
}

// Print a hexadecimal dump of bytes
fn print_hex_dump(data: &[u8], max_len: usize) {
    let len = std::cmp::min(data.len(), max_len);

    for i in 0..len {
        print!("{:02x} ", data[i]);

        if (i + 1) % 16 == 0 || i == len - 1 {
            println!();
        }
    }
}
