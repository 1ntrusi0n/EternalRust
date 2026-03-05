//! Software overwrite wiper used for USB flash drives and magnetic HDDs.
//!
//! This module performs direct block writes to the raw device and verifies the
//! final pass by reading data back and comparing expected bytes.

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::error::WipeError;
use crate::types::{
    DeviceInfo, ProgressCallback, ProgressInfo, WipeMethod, WipePass, WipeResult, WipeStandard,
};

/// Size of the write buffer used per I/O operation (4 MiB).
const WRITE_BUF_BYTES: usize = 4 * 1024 * 1024;

/// How often (in bytes) the progress callback is fired during a pass.
const PROGRESS_INTERVAL: u64 = 64 * 1024 * 1024;

pub struct UsbWiper<'a> {
    pub device: &'a DeviceInfo,
    pub callback: Option<Arc<ProgressCallback>>,
}

#[derive(Debug, Clone, Copy)]
enum ResolvedPass {
    Fixed(u8),
    RandomStream { seed: [u8; 32], invert: bool },
}

impl<'a> UsbWiper<'a> {
    /// Build the pass schedule for the requested standard.
    pub fn pass_schedule(standard: &WipeStandard) -> Vec<WipePass> {
        match standard {
            WipeStandard::Nist80088Clear | WipeStandard::Nist80088Purge => {
                vec![WipePass::Fixed(0x00)]
            }
            WipeStandard::DoD522022M => {
                vec![WipePass::Fixed(0x00), WipePass::Fixed(0xFF), WipePass::Random]
            }
            WipeStandard::DoD522022MECE => vec![
                WipePass::Random,
                WipePass::Fixed(0x00),
                WipePass::Random,
                WipePass::Fixed(0x00),
                WipePass::Fixed(0xFF),
                WipePass::Random,
                WipePass::Random,
                WipePass::Fixed(0xFF),
                WipePass::Random,
            ],
            WipeStandard::Gutmann => gutmann_passes(),
            WipeStandard::Custom { passes } => passes.clone(),
        }
    }

    /// Execute the wipe and return a result record.
    pub fn wipe(&self, standard: &WipeStandard) -> Result<WipeResult, WipeError> {
        let started_at = unix_now();
        let passes = Self::pass_schedule(standard);
        if passes.is_empty() {
            return Err(WipeError::WipeAborted(
                "no wipe passes configured (Custom pass schedule is empty)".into(),
            ));
        }

        let total_passes = passes.len() as u32;
        let mut bytes_processed: u64 = 0;
        let mut messages: Vec<String> = Vec::new();
        let device_size = self.device.size_bytes;
        if device_size == 0 {
            return Err(WipeError::DeviceSizeUnknown);
        }

        let resolved_passes = Self::resolve_passes(&passes)?;

        log::info!(
            "USB overwrite wipe: {} - {} passes on {} ({} bytes)",
            self.device.path,
            total_passes,
            format_size(device_size),
            device_size
        );

        for (pass_idx, pass_spec) in passes.iter().enumerate() {
            let pass_num = pass_idx as u32 + 1;
            let desc = pass_description(pass_spec, pass_num, total_passes);
            log::info!("{}", desc);

            let written = self.write_pass(
                &resolved_passes[pass_idx],
                pass_num,
                total_passes,
                device_size,
                &desc,
            )?;
            bytes_processed += written;
        }

        // Verify the final pass. Any mismatch is a hard failure.
        let last_pass = resolved_passes
            .last()
            .ok_or_else(|| WipeError::WipeAborted("no resolved wipe passes".into()))?;
        self.verify_pass(last_pass, device_size)?;
        messages.push("Verification pass: PASSED".into());

        Ok(WipeResult {
            success: true,
            device_path: self.device.path.clone(),
            standard_requested: standard.clone(),
            method_used: WipeMethod::SoftwareOverwrite {
                passes: Self::pass_schedule(standard),
            },
            bytes_processed,
            passes_completed: total_passes,
            verified: true,
            started_at_unix: started_at,
            completed_at_unix: unix_now(),
            messages,
        })
    }

    fn resolve_passes(passes: &[WipePass]) -> Result<Vec<ResolvedPass>, WipeError> {
        let mut resolved = Vec::with_capacity(passes.len());
        let mut entropy = rand::thread_rng();

        for pass in passes {
            let next = match pass {
                WipePass::Fixed(byte) => ResolvedPass::Fixed(*byte),
                WipePass::Random => {
                    let mut seed = [0u8; 32];
                    entropy.fill_bytes(&mut seed);
                    ResolvedPass::RandomStream {
                        seed,
                        invert: false,
                    }
                }
                WipePass::Complement => {
                    let prev = resolved.last().ok_or_else(|| {
                        WipeError::WipeAborted(
                            "invalid pass schedule: Complement cannot be the first pass".into(),
                        )
                    })?;
                    match prev {
                        ResolvedPass::Fixed(byte) => ResolvedPass::Fixed(!byte),
                        ResolvedPass::RandomStream { seed, invert } => {
                            ResolvedPass::RandomStream {
                                seed: *seed,
                                invert: !invert,
                            }
                        }
                    }
                }
            };
            resolved.push(next);
        }

        Ok(resolved)
    }

    fn write_pass(
        &self,
        pattern: &ResolvedPass,
        pass_num: u32,
        total_passes: u32,
        device_size: u64,
        desc: &str,
    ) -> Result<u64, WipeError> {
        let mut file = open_device_rw(&self.device.path)?;
        file.seek(SeekFrom::Start(0))?;

        let mut buf = vec![0u8; WRITE_BUF_BYTES];
        let mut stream_rng = match pattern {
            ResolvedPass::RandomStream { seed, .. } => Some(StdRng::from_seed(*seed)),
            ResolvedPass::Fixed(_) => None,
        };
        let mut bytes_written: u64 = 0;
        let mut last_report: u64 = 0;

        loop {
            let remaining = device_size.saturating_sub(bytes_written);
            if remaining == 0 {
                break;
            }
            let chunk = remaining.min(WRITE_BUF_BYTES as u64) as usize;

            match pattern {
                ResolvedPass::Fixed(byte) => buf[..chunk].fill(*byte),
                ResolvedPass::RandomStream { invert, .. } => {
                    let rng = stream_rng
                        .as_mut()
                        .ok_or_else(|| WipeError::WipeAborted("random stream RNG missing".into()))?;
                    rng.fill_bytes(&mut buf[..chunk]);
                    if *invert {
                        for b in &mut buf[..chunk] {
                            *b = !*b;
                        }
                    }
                }
            }

            file.write_all(&buf[..chunk])?;
            bytes_written += chunk as u64;

            if bytes_written - last_report >= PROGRESS_INTERVAL {
                last_report = bytes_written;
                if let Some(cb) = &self.callback {
                    cb(ProgressInfo {
                        bytes_done: bytes_written,
                        total_bytes: device_size,
                        current_pass: pass_num,
                        total_passes,
                        percentage: (bytes_written as f64 / device_size as f64) * 100.0,
                        description: desc.to_string(),
                    });
                }
            }
        }

        // Ensure data is committed to media.
        file.sync_all()?;

        if let Some(cb) = &self.callback {
            cb(ProgressInfo {
                bytes_done: bytes_written,
                total_bytes: device_size,
                current_pass: pass_num,
                total_passes,
                percentage: 100.0,
                description: desc.to_string(),
            });
        }

        Ok(bytes_written)
    }

    fn verify_pass(&self, pattern: &ResolvedPass, device_size: u64) -> Result<(), WipeError> {
        let mut file = open_device_ro(&self.device.path)?;
        file.seek(SeekFrom::Start(0))?;

        let mut actual = vec![0u8; WRITE_BUF_BYTES];
        let mut expected = vec![0u8; WRITE_BUF_BYTES];
        let mut stream_rng = match pattern {
            ResolvedPass::RandomStream { seed, .. } => Some(StdRng::from_seed(*seed)),
            ResolvedPass::Fixed(_) => None,
        };
        let mut offset: u64 = 0;

        loop {
            let remaining = device_size.saturating_sub(offset);
            if remaining == 0 {
                break;
            }
            let chunk = remaining.min(WRITE_BUF_BYTES as u64) as usize;
            file.read_exact(&mut actual[..chunk])?;

            match pattern {
                ResolvedPass::Fixed(byte) => expected[..chunk].fill(*byte),
                ResolvedPass::RandomStream { invert, .. } => {
                    let rng = stream_rng
                        .as_mut()
                        .ok_or_else(|| WipeError::WipeAborted("random stream RNG missing".into()))?;
                    rng.fill_bytes(&mut expected[..chunk]);
                    if *invert {
                        for b in &mut expected[..chunk] {
                            *b = !*b;
                        }
                    }
                }
            }

            for i in 0..chunk {
                if actual[i] != expected[i] {
                    return Err(WipeError::VerificationFailed {
                        offset: offset + i as u64,
                        expected: expected[i],
                        found: actual[i],
                    });
                }
            }

            offset += chunk as u64;
        }

        Ok(())
    }
}

/// Returns the full Gutmann 35-pass schedule (Gutmann, 1996).
fn gutmann_passes() -> Vec<WipePass> {
    let mut passes: Vec<WipePass> = Vec::with_capacity(35);

    for _ in 0..4 {
        passes.push(WipePass::Random);
    }

    let fixed: &[u8] = &[
        0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB,
    ];
    for &b in fixed {
        passes.push(WipePass::Fixed(b));
    }

    for _ in 0..4 {
        passes.push(WipePass::Random);
    }

    passes
}

fn open_device_rw(path: &str) -> Result<std::fs::File, WipeError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                WipeError::PermissionDenied
            } else {
                WipeError::Io(e)
            }
        })
}

fn open_device_ro(path: &str) -> Result<std::fs::File, WipeError> {
    std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                WipeError::PermissionDenied
            } else {
                WipeError::Io(e)
            }
        })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn format_size(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    }
}

fn pass_description(spec: &WipePass, pass_num: u32, total: u32) -> String {
    let pattern = match spec {
        WipePass::Fixed(b) => format!("0x{:02X}", b),
        WipePass::Random => "random".into(),
        WipePass::Complement => "complement(previous pass)".into(),
    };
    format!("Pass {}/{} - pattern: {}", pass_num, total, pattern)
}
