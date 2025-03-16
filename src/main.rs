use regex::Regex;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::thread;
use std::time::Duration;

// define memory region structure
struct MemoryRegion {
    start_addr: u64,
    end_addr: u64,
    permissions: String,
    offset: u64,
    dev: String,
    inode: u64,
    path: Option<String>,
}

// get all executable memory regions for a process
fn get_executable_regions(pid: &str) -> Result<Vec<MemoryRegion>, Box<dyn Error>> {
    let maps_content = fs::read_to_string(format!("/proc/{}/maps", pid))?;

    // re to parse memory region lines
    let re = Regex::new(r"([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]{4})\s+([0-9a-f]+)\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)(?:\s+(.+))?").unwrap();

    let mut executable_regions = Vec::new();

    // parse each line
    for line in maps_content.lines() {
        if let Some(caps) = re.captures(line) {
            let start_addr = u64::from_str_radix(&caps[1], 16)?;
            let path = caps.get(7).map(|m| m.as_str().to_string());

            if start_addr == 0xffffffffff600000 || path.as_deref() == Some("[vsyscall]") {
                continue;
            }

            let region = MemoryRegion {
                start_addr: u64::from_str_radix(&caps[1], 16)?,
                end_addr: u64::from_str_radix(&caps[2], 16)?,
                permissions: caps[3].to_string(),
                offset: u64::from_str_radix(&caps[4], 16)?,
                dev: caps[5].to_string(),
                inode: caps[6].parse()?,
                path: caps.get(7).map(|m| m.as_str().to_string()),
            };

            if region.permissions.contains('x') {
                executable_regions.push(region);
            }
        }
    }

    Ok(executable_regions)
}

// read memory content from a process's address space
fn read_memory(pid: &str, start_addr: u64, size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut mem_file = File::open(format!("/proc/{}/mem", pid))?;
    let mut buffer = vec![0u8; size];

    mem_file.seek(SeekFrom::Start(start_addr))?;
    mem_file.read_exact(&mut buffer)?;

    Ok(buffer)
}

// calculate a simple hash for quick data comparison
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0;
    for byte in data {
        hash = hash.wrapping_mul(31).wrapping_add(*byte as u64)
    }
    hash
}

// output memory content in a formatted hexadecimal view
fn print_hex_dump(data: &[u8], base_addr: u64, label: &str) {
    if data.is_empty() {
        println!("    {}: <empty>", label);
        return;
    }

    println!("    {} ({} bytes):", label, data.len());

    // Display as hex in a nicely formatted way
    for (i, byte) in data.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n      {:08x}:  ", base_addr as usize + i);
        }
        print!("{:02x} ", byte);

        // Add an extra space after 8 bytes for better readability
        if (i + 1) % 8 == 0 && (i + 1) % 16 != 0 {
            print!(" ");
        }
    }
    println!("\n");
}

fn main() -> Result<(), Box<dyn Error>> {
    // command line args: PID and interval
    let pid = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "self".to_string());

    let interval_ms = std::env::args()
        .nth(2)
        .map(|s| s.parse::<u64>().unwrap_or(1000))
        .unwrap_or(1000);

    println!(
        "Monitoring executable memory regions for PID {} every {}ms...",
        pid, interval_ms
    );

    // key: memory start address, value: content hash, region size, path
    let mut last_regions: HashMap<u64, (u64, u64, Option<String>)> = HashMap::new();
    let mut scan_count = 0;

    loop {
        scan_count += 1;
        println!("\n--- Scan #{} ---", scan_count);

        match get_executable_regions(&pid) {
            Ok(executable_regions) => {
                println!(
                    "Found {} executable memory regions",
                    executable_regions.len()
                );

                let current_addrs: Vec<u64> =
                    executable_regions.iter().map(|r| r.start_addr).collect();

                for region in &executable_regions {
                    let sample_size =
                        usize::min(64, (region.end_addr - region.start_addr) as usize);

                    match read_memory(&pid, region.start_addr, sample_size) {
                        Ok(current_content) => {
                            let content_hash = simple_hash(&current_content);

                            // check if this is a new region or content has changed
                            if let Some((prev_hash, prev_size, prev_path)) =
                                last_regions.get(&region.start_addr)
                            {
                                // check for content changes
                                if *prev_hash != content_hash {
                                    println!(
                                        "[CHANGED] Region at 0x{:x}-0x{:x} ({}) has changed content",
                                        region.start_addr,
                                        region.end_addr,
                                        region.path.as_deref().unwrap_or("[anonymous]")
                                    );

                                    let display_size = usize::min(64, current_content.len());
                                    println!("  New content (first {} bytes):", display_size);

                                    for (i, byte) in
                                        current_content.iter().take(display_size).enumerate()
                                    {
                                        if i % 16 == 0 {
                                            print!(
                                                "\n    {:08x}:  ",
                                                region.start_addr as usize + i
                                            );
                                        }
                                        print!("{:02x} ", byte);
                                    }
                                    println!("\n");
                                }

                                // check for size changes
                                if *prev_size != region.end_addr - region.start_addr {
                                    println!(
                                        "[RESIZED] Region at 0x{:x} changed size from {} to {} bytes",
                                        region.start_addr,
                                        prev_size,
                                        region.end_addr - region.start_addr
                                    );
                                }
                            } else {
                                println!(
                                    "[NEW] Executable region at 0x{:x}-0x{:x} ({}) detected",
                                    region.start_addr,
                                    region.end_addr,
                                    region.path.as_deref().unwrap_or("[anonymous]")
                                );
                            }

                            last_regions.insert(
                                region.start_addr,
                                (
                                    content_hash,
                                    region.end_addr - region.start_addr,
                                    region.path.clone(),
                                ),
                            );
                        }
                        Err(e) => {
                            if region.path.as_deref() == Some("[vdso]")
                                || region.path.as_deref() == Some("[vvar]")
                            {
                                println!(
                                    "Special region at 0x{:x}-0x{:x} ({}): Memory not directly readable",
                                    region.start_addr,
                                    region.end_addr,
                                    region.path.as_deref().unwrap_or("[unknown]")
                                );
                            } else {
                                println!("Cannot read memory at 0x{:x}: {}", region.start_addr, e);
                            }

                            last_regions.insert(
                                region.start_addr,
                                (0, region.end_addr - region.start_addr, region.path.clone()),
                            );
                        }
                    }
                }

                // check for regions that have disappeared
                let removed_addrs: Vec<u64> = last_regions
                    .keys()
                    .filter(|addr| !current_addrs.contains(addr))
                    .cloned()
                    .collect();

                for addr in removed_addrs {
                    if let Some((_, size, path)) = last_regions.get(&addr) {
                        println!(
                            "[REMOVED] Executable region at 0x{:x} ({} bytes, {}) is no longer present",
                            addr,
                            size,
                            path.as_ref().map_or("[anonymous]", |s| s.as_str())
                        );
                        last_regions.remove(&addr);
                    }
                }
            }
            Err(e) => {
                println!("Error getting memory regions: {}", e);

                if e.to_string().contains("No such file or directory") {
                    println!("Process {} may have terminated. Exiting...", pid);
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(interval_ms));
    }

    Ok(())
}
