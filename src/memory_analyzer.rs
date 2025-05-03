use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use procfs::process::{MMapPath, Process};

use crate::models::ExecutablePage;

pub struct MemoryAnalyzer {
    pub pid: i32,
}

impl MemoryAnalyzer {
    pub fn new(pid: i32) -> Self {
        Self { pid }
    }

    // get all executable memory pages for the process
    pub fn get_executable_pages(&self) -> Result<Vec<ExecutablePage>> {
        let process = Process::new(self.pid).context("Failed to open process")?;
        let maps = process.maps().context("Failed to read memory maps")?;

        let mut executable_pages = Vec::new();

        for map in maps {
            // check if memory is executable - looking for EXECUTE in the permissions
            let perms_str = format!("{:?}", map.perms);

            if perms_str.contains("EXECUTE") {
                let source_file = match &map.pathname {
                    MMapPath::Path(path) => Some(PathBuf::from(path)),
                    _ => None,
                };

                executable_pages.push(ExecutablePage {
                    address: map.address.0 as usize,
                    size: (map.address.1 - map.address.0) as usize,
                    timestamp: SystemTime::now(),
                    source_file,
                    content: None,
                    protection_flags: Self::perms_to_flags(&perms_str),
                });
            }
        }

        Ok(executable_pages)
    }

    // read memory page content
    pub fn read_memory_page(&self, page: &mut ExecutablePage) -> Result<()> {
        let mut content = vec![0u8; page.size];

        // read from /proc/[pid]/mem
        let mem_path = format!("/proc/{}/mem", self.pid);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(mem_path)
            .context("Failed to open process memory")?;

        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(page.address as u64))
            .context("Failed to seek to memory address")?;
        file.read_exact(&mut content)
            .context("Failed to read memory content")?;

        page.content = Some(content);
        Ok(())
    }

    // convert permission string to flags
    fn perms_to_flags(perms: &str) -> u32 {
        let mut flags: u32 = 0;

        if perms.contains("READ") {
            flags |= libc::PROT_READ as u32;
        }

        if perms.contains("WRITE") {
            flags |= libc::PROT_WRITE as u32;
        }

        if perms.contains("EXECUTE") {
            flags |= libc::PROT_EXEC as u32;
        }

        flags
    }
}
