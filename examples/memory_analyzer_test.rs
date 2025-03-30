// examples/memory_analyzer_test.rs
use emt::MemoryAnalyzer;
use std::env;

fn main() -> anyhow::Result<()> {
    // Get current process PID or a specific PID from command line
    let pid = match env::args().nth(1) {
        Some(arg) => arg.parse::<i32>().unwrap_or(std::process::id() as i32),
        None => std::process::id() as i32,
    };

    println!("Analyzing process with PID: {}", pid);

    // Create memory analyzer for the process
    let analyzer = MemoryAnalyzer::new(pid);

    // Get all executable pages
    let pages = analyzer.get_executable_pages()?;

    println!("Found {} executable memory pages:", pages.len());

    // Print details of the first 5 pages
    for (i, page) in pages.iter().take(5).enumerate() {
        println!(
            "Page {}: Address: 0x{:x}, Size: {} bytes",
            i + 1,
            page.address,
            page.size
        );

        if let Some(source) = &page.source_file {
            println!("  Source: {}", source.display());
        } else {
            println!("  Source: [anonymous]");
        }

        println!(
            "  Protection: {}{}{}",
            if page.protection_flags & (libc::PROT_READ as u32) != 0 {
                "r"
            } else {
                "-"
            },
            if page.protection_flags & (libc::PROT_WRITE as u32) != 0 {
                "w"
            } else {
                "-"
            },
            if page.protection_flags & (libc::PROT_EXEC as u32) != 0 {
                "x"
            } else {
                "-"
            }
        );
    }

    if pages.len() > 5 {
        println!("... and {} more pages", pages.len() - 5);
    }

    // Try to read content of one page (optional test for 200-hour project)
    if !pages.is_empty() {
        let mut page = pages[0].clone();

        match analyzer.read_memory_page(&mut page) {
            Ok(_) => {
                if let Some(content) = &page.content {
                    println!("\nSuccessfully read page content. First 16 bytes:");

                    // Print the first 16 bytes in hex
                    for byte in content.iter().take(16) {
                        print!("{:02x} ", byte);
                    }
                    println!();
                }
            }
            Err(e) => println!("Failed to read memory content: {}", e),
        }
    }

    println!("Memory analyzer test completed successfully");
    Ok(())
}
