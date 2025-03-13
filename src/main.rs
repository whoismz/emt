use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};

use regex::Regex;

struct MemoryRegion {
    start_addr: u64,
    end_addr: u64,
    permissions: String,
    offset: u64,
    dev: String,
    inode: u64,
    path: Option<String>,
}

fn read_memory(pid: &str, start_addr: u64, size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut mem_file = File::open(format!("/proc/{}/mem", pid))?;
    let mut buffer = vec![0u8; size];

    mem_file.seek(SeekFrom::Start(start_addr))?;
    mem_file.read_exact(&mut buffer)?;

    Ok(buffer)
}

fn get_executable_regions(pid: &str) -> Result<Vec<MemoryRegion>, Box<dyn Error>> {
    let maps_content = fs::read_to_string(format!("/proc/{}/maps", pid))?;

    let re = Regex::new(r"([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]{4})\s+([0-9a-f]+)\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)(?:\s+(.+))?").unwrap();

    let mut executable_regions = Vec::new();

    for line in maps_content.lines() {
        if let Some(caps) = re.captures(line) {
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

fn main() -> Result<(), Box<dyn Error>> {
    let pid = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "self".to_string());

    println!("[pid]: {}", pid);

    let executable_regions = get_executable_regions(&pid)?;

    println!(
        "Found {} executable memory regions:",
        executable_regions.len()
    );

    for (i, region) in executable_regions.iter().enumerate() {
        println!(
            "{}. Region 0x{:x}-0x{:x} {} Size: {} bytes {}",
            i + 1,
            region.start_addr,
            region.end_addr,
            region.permissions,
            region.end_addr - region.start_addr,
            region.path.as_deref().unwrap_or("[anonymous]")
        );

        let sample_size = usize::min(1024, (region.end_addr - region.start_addr) as usize);

        match read_memory(&pid, region.start_addr, sample_size) {
            Ok(memory) => {
                println!("  First {} bytes:", sample_size);

                for (i, byte) in memory.iter().enumerate() {
                    if i % 16 == 0 {
                        print!("\n    {:08x}:  ", region.start_addr as usize + i);
                    }
                    print!("{:02x} ", byte);
                }
                println!("\n");
            }
            Err(e) => {
                println!("  Error reading memory: {}", e);
            }
        }
        println!();
    }

    Ok(())
}
