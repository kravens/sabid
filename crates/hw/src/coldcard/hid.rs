//! Linux hidraw access to a Coldcard (vendor d13e, product cc10), as Wasabi's `UsbHidLinux`:
//! devices found through `/sys/class/hidraw/*/device/uevent`, driven with plain read/write.
//! Output reports are 65 bytes (report id 0 first), input reports 64 bytes.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

pub const VENDOR_ID: u16 = 0xd13e;
pub const PRODUCT_ID: u16 = 0xcc10;
pub const OUTPUT_REPORT_LEN: usize = 65;
pub const INPUT_REPORT_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum HidError {
    #[error("No Coldcard is connected. Connect (and Enable) USB on the device.")]
    NotFound,
    #[error("Cannot open '{0}': {1}. If this is a permissions error, add a udev rule for d13e:cc10.")]
    Permission(String, String),
    #[error("HID io: {0}")]
    Io(String),
    #[error("Coldcard did not respond in time.")]
    Timeout,
}

pub struct HidDevice {
    file: File,
    pub node: String,
}

pub fn enumerate() -> Vec<String> {
    let mut nodes = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/class/hidraw") else { return nodes };
    let wanted = format!("HID_ID=0003:{:08X}:{:08X}", VENDOR_ID, PRODUCT_ID);
    for e in rd.flatten() {
        let uevent = e.path().join("device").join("uevent");
        if let Ok(text) = std::fs::read_to_string(&uevent) {
            if text.lines().any(|l| l.trim().eq_ignore_ascii_case(&wanted)) {
                nodes.push(format!("/dev/{}", e.file_name().to_string_lossy()));
            }
        }
    }
    nodes.sort();
    nodes
}

impl HidDevice {
    pub fn open() -> Result<Self, HidError> {
        let nodes = enumerate();
        if nodes.is_empty() {
            return Err(HidError::NotFound);
        }
        let mut last = None;
        for node in nodes {
            match OpenOptions::new().read(true).write(true).open(&node) {
                Ok(file) => return Ok(Self { file, node }),
                Err(e) => last = Some(HidError::Permission(node, e.to_string())),
            }
        }
        Err(last.unwrap_or(HidError::NotFound))
    }

    pub fn write_report(&mut self, report: &[u8]) -> Result<(), HidError> {
        if report.len() != OUTPUT_REPORT_LEN {
            return Err(HidError::Io(format!("output report must be {OUTPUT_REPORT_LEN} bytes")));
        }
        let n = self.file.write(report).map_err(|e| HidError::Io(e.to_string()))?;
        if n != report.len() {
            return Err(HidError::Io(format!("short HID write ({n} of {})", report.len())));
        }
        Ok(())
    }

    /// One 64-byte input report, or a timeout.
    pub fn read_report(&mut self, timeout_ms: i32) -> Result<[u8; INPUT_REPORT_LEN], HidError> {
        let mut pfd = libc::pollfd { fd: self.file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if r < 0 {
            return Err(HidError::Io(std::io::Error::last_os_error().to_string()));
        }
        if r == 0 {
            return Err(HidError::Timeout);
        }
        let mut buf = [0u8; INPUT_REPORT_LEN];
        let n = self.file.read(&mut buf).map_err(|e| HidError::Io(e.to_string()))?;
        if n < INPUT_REPORT_LEN {
            return Err(HidError::Io(format!("Coldcard sent a truncated {n}-byte HID report.")));
        }
        Ok(buf)
    }
}
