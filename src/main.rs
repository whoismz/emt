use std::fs;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
	let pid = 1;

	let status = fs::read_to_string(format!("/proc/{}/status", pid))?;
	println!("Process {} status:\n{}", pid, status);

	let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
	println!("\nProcess {} memory maps:\n{}", pid, maps);

	Ok(())
}
