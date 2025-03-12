use std::fs;
use std::error::Error;
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


fn main() -> Result<(), Box<dyn Error>> {
	let pid = std::env::args().nth(1).unwrap_or_else(|| "self".to_string());
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

	println!("Executable memory regions for PID {}:", pid);
	for (i, region) in executable_regions.iter().enumerate() {
		println!("{}: 0x{:x}-0x{:x} {} ({} bytes) {}",
			i + 1,
			region.start_addr,
			region.end_addr,
			region.permissions,
			region.end_addr - region.start_addr,
			region.path.as_deref().unwrap_or("[anonymous]")
		);
	}

	Ok(())
}
