// examples/analyzer_diagnostic.rs
use emt::MemoryAnalyzer;
use std::env;

fn main() -> anyhow::Result<()> {
    // Get target process ID, default to current process
    let pid = match env::args().nth(1) {
        Some(arg) => arg.parse::<i32>().unwrap_or(std::process::id() as i32),
        None => std::process::id() as i32,
    };

    println!("=== Memory Analyzer Diagnostic ===");
    println!("Target PID: {}", pid);

    // Create memory analyzer
    let analyzer = MemoryAnalyzer::new(pid);

    // Try to get executable pages
    match analyzer.get_executable_pages() {
        Ok(pages) => {
            println!("Successfully found {} executable pages", pages.len());

            if pages.is_empty() {
                println!("WARNING: No executable pages found!");
            } else {
                println!("\nFirst 10 executable pages:");
                for (i, page) in pages.iter().take(10).enumerate() {
                    println!("Page #{}", i + 1);
                    println!("  Address: 0x{:x}", page.address);
                    println!("  Size: {} bytes", page.size);
                    println!("  Protection: {:x}", page.protection_flags);
                    if let Some(source) = &page.source_file {
                        println!("  Source: {}", source.display());
                    } else {
                        println!("  Source: [anonymous]");
                    }
                    println!();
                }
            }

            // Try reading the first page content
            if !pages.is_empty() {
                let mut page = pages[0].clone();
                match analyzer.read_memory_page(&mut page) {
                    Ok(_) => {
                        if let Some(content) = &page.content {
                            println!("Successfully read page content.");
                            println!("First 16 bytes:");
                            for (i, &byte) in content.iter().take(16).enumerate() {
                                print!("{:02x} ", byte);
                                if (i + 1) % 8 == 0 {
                                    println!();
                                }
                            }
                            println!();
                        }
                    }
                    Err(e) => {
                        println!("Failed to read memory content: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Error getting executable pages: {}", e);
            println!("This may be due to permissions or process issues.");
        }
    }

    println!("\n=== System Information ===");
    // Check current user and permissions
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    println!("Running as: UID={}, EUID={}", uid, euid);

    // Check /proc filesystem
    let proc_exists = std::path::Path::new("/proc").exists();
    println!("/proc exists: {}", proc_exists);

    // Fix the temporary value issue
    let proc_path = format!("/proc/{}", pid);
    let target_proc = std::path::Path::new(&proc_path);
    println!("/proc/{} exists: {}", pid, target_proc.exists());

    if target_proc.exists() {
        let maps_path = target_proc.join("maps");
        println!("/proc/{}/maps exists: {}", pid, maps_path.exists());

        if maps_path.exists() {
            match std::fs::read_to_string(&maps_path) {
                Ok(content) => {
                    println!("First 5 lines of /proc/{}/maps:", pid);
                    for (i, line) in content.lines().take(5).enumerate() {
                        println!("  {}: {}", i + 1, line);
                    }
                }
                Err(e) => {
                    println!("Could not read /proc/{}/maps: {}", pid, e);
                }
            }
        }
    }

    println!("\n=== Diagnostic Complete ===");
    Ok(())
}
