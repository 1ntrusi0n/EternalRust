//! Custom NVMe admin command engine.
//!
//! Implements a thin NVMe command-line interface (nvme-cli) in pure Rust,
//! sending admin commands directly to the NVMe controller via the Linux
//! kernel's `NVME_IOCTL_ADMIN_CMD` ioctl (`/dev/nvmeN`).
//!
//! ## Commands implemented
//!
//! | Opcode | Name                 | Purpose                                   |
//! |--------|----------------------|-------------------------------------------|
//! | 0x06   | Identify Controller  | Read SANICAP / model / serial             |
//! | 0x80   | Format NVM           | Low-level reformat with secure erase      |
//! | 0x84   | Sanitize             | Hardware-accelerated multi-mode erase     |
//! | 0x14   | Get Log Page         | Poll Sanitize Status log (0x81)           |
//!
//! ## Erase priority (auto-selected)
//!
//! 1. Sanitize — Crypto Erase (fastest, strongest)
//! 2. Sanitize — Block Erase  (overwrites all NAND blocks including spare)
//! 3. Sanitize — Overwrite    (16-pass logical overwrite)
//! 4. Format NVM — Crypto Erase (SES=010b)
//! 5. Format NVM — User Data Erase (SES=001b)
//!
//! ## NVMe controller vs namespace paths
//!
//! Admin commands must be directed to the **controller** device (`/dev/nvme0`),
//! not the namespace (`/dev/nvme0n1`).  The namespace ID (NSID) is encoded in
//! the command when the erase is namespace-scoped, or 0xFFFFFFFF for all
//! namespaces.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::WipeError;
use crate::types::{DeviceInfo, WipeMethod, WipeResult, WipeStandard};

pub struct NvmeWiper<'a> {
    pub device: &'a DeviceInfo,
    /// Controller device path (e.g. `/dev/nvme0`).
    pub ctrl_path: String,
}

impl<'a> NvmeWiper<'a> {
    pub fn new(device: &'a DeviceInfo, ctrl_path: String) -> Self {
        Self { device, ctrl_path }
    }

    /// Query the SANICAP field from Identify Controller data.
    ///
    /// Returns a bitmask: bit 0 = Crypto Erase, bit 1 = Block Erase,
    /// bit 2 = Overwrite.  Returns 0 if the controller does not support
    /// Sanitize or if the command fails.
    pub fn identify_sanitize_caps(ctrl_path: &str) -> Result<u8, WipeError> {
        #[cfg(target_os = "linux")]
        return linux::nvme_identify_sanitize_caps(ctrl_path);

        #[cfg(not(target_os = "linux"))]
        return Ok(0);
    }

    /// Perform the best available NVMe wipe.
    pub fn wipe(&self, standard: &WipeStandard, prefer_crypto: bool) -> Result<WipeResult, WipeError> {
        #[cfg(target_os = "linux")]
        return self.wipe_linux(standard, prefer_crypto);

        #[cfg(not(target_os = "linux"))]
        return Err(WipeError::PlatformNotSupported);
    }
}

// ─── Linux implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
impl<'a> NvmeWiper<'a> {
    fn wipe_linux(&self, standard: &WipeStandard, prefer_crypto: bool) -> Result<WipeResult, WipeError> {
        let started_at = unix_now();
        let path = &self.device.path;
        let caps = self.device.nvme_sanitize_caps;

        // Choose the best available erase method.
        let (method, description) = self.select_erase_method(caps, prefer_crypto, standard)?;

        log::info!("NVMe wipe: {} — {}", path, description);

        match &method {
            WipeMethod::NvmeSanitizeCryptoErase => {
                linux::nvme_sanitize(&self.ctrl_path, SanitizeAction::CryptoErase, 0, false)?;
                linux::wait_for_sanitize_completion(&self.ctrl_path)?;
            }
            WipeMethod::NvmeSanitizeBlockErase => {
                linux::nvme_sanitize(&self.ctrl_path, SanitizeAction::BlockErase, 0, false)?;
                linux::wait_for_sanitize_completion(&self.ctrl_path)?;
            }
            WipeMethod::NvmeSanitizeOverwrite { pass_count } => {
                linux::nvme_sanitize(&self.ctrl_path, SanitizeAction::Overwrite, *pass_count, false)?;
                linux::wait_for_sanitize_completion(&self.ctrl_path)?;
            }
            WipeMethod::NvmeFormatCryptoErase => {
                linux::nvme_format_nvm(&self.ctrl_path, 0, SecureEraseSettings::CryptoErase)?;
            }
            WipeMethod::NvmeFormatUserDataErase => {
                linux::nvme_format_nvm(&self.ctrl_path, 0, SecureEraseSettings::UserDataErase)?;
            }
            _ => unreachable!(),
        }

        log::info!("NVMe wipe completed: {}", path);

        Ok(WipeResult {
            success: true,
            device_path: path.clone(),
            standard_requested: standard.clone(),
            method_used: method,
            bytes_processed: self.device.size_bytes,
            passes_completed: 1,
            verified: false,
            started_at_unix: started_at,
            completed_at_unix: unix_now(),
            messages: vec![description],
        })
    }

    fn select_erase_method(
        &self,
        caps: u8,
        prefer_crypto: bool,
        standard: &WipeStandard,
    ) -> Result<(WipeMethod, String), WipeError> {
        let crypto_ok = caps & 0x01 != 0;
        let block_ok = caps & 0x02 != 0;
        let overwrite_ok = caps & 0x04 != 0;

        // NIST Purge / DoD — prefer hardware Sanitize over Format NVM
        if crypto_ok && prefer_crypto {
            return Ok((
                WipeMethod::NvmeSanitizeCryptoErase,
                "NVMe Sanitize — Cryptographic Erase (NIST 800-88 Purge)".into(),
            ));
        }
        if block_ok {
            return Ok((
                WipeMethod::NvmeSanitizeBlockErase,
                "NVMe Sanitize — Block Erase (NIST 800-88 Purge)".into(),
            ));
        }
        if crypto_ok {
            return Ok((
                WipeMethod::NvmeSanitizeCryptoErase,
                "NVMe Sanitize — Cryptographic Erase".into(),
            ));
        }
        if overwrite_ok {
            return Ok((
                WipeMethod::NvmeSanitizeOverwrite { pass_count: 1 },
                "NVMe Sanitize — Overwrite (1 pass)".into(),
            ));
        }

        // Fall back to Format NVM
        log::warn!("NVMe Sanitize not supported; falling back to Format NVM");
        Ok((
            WipeMethod::NvmeFormatUserDataErase,
            "NVMe Format NVM — User Data Erase (SES=001b)".into(),
        ))
    }
}

// ─── Linux NVMe ioctl primitives ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::*;
    use libc::{c_int, c_void, ioctl};
    use std::os::unix::io::AsRawFd;

    // NVME_IOCTL_ADMIN_CMD = _IOWR('N', 0x41, struct nvme_passthru_cmd)
    // = (3<<30) | (0x4E<<8) | 0x41 | (72<<16) = 0xC0484E41
    const NVME_IOCTL_ADMIN_CMD: libc::c_ulong = 0xC0484E41;

    // NVMe admin opcodes
    const NVME_ADMIN_IDENTIFY: u8 = 0x06;
    const NVME_ADMIN_FORMAT_NVM: u8 = 0x80;
    const NVME_ADMIN_SANITIZE: u8 = 0x84;
    const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;

    // Sanitize log page identifier
    const NVME_LOG_SANITIZE_STATUS: u8 = 0x81;

    // Sanitize status (SSTAT field)
    const SANITIZE_STATUS_IDLE: u16 = 0x0000;
    const SANITIZE_STATUS_SUCCEEDED: u16 = 0x0101;
    const SANITIZE_STATUS_IN_PROGRESS: u16 = 0x0002;
    const SANITIZE_STATUS_FAILED: u16 = 0x0103;

    // Identify Controller CNS value
    const CNS_CONTROLLER: u32 = 0x01;

    // ── NVMe passthrough command structure ────────────────────────────────────
    //
    // `struct nvme_passthru_cmd` from <linux/nvme_ioctl.h> (72 bytes)

    #[repr(C)]
    pub struct NvmePassthruCmd {
        pub opcode: u8,
        pub flags: u8,
        pub rsvd1: u16,
        pub nsid: u32,
        pub cdw2: u32,
        pub cdw3: u32,
        pub metadata: u64,
        pub addr: u64,
        pub metadata_len: u32,
        pub data_len: u32,
        pub cdw10: u32,
        pub cdw11: u32,
        pub cdw12: u32,
        pub cdw13: u32,
        pub cdw14: u32,
        pub cdw15: u32,
        pub timeout_ms: u32,
        pub result: u32,
    }

    impl Default for NvmePassthruCmd {
        fn default() -> Self {
            // SAFETY: all-zero is a valid initialiser for this POD struct.
            unsafe { std::mem::zeroed() }
        }
    }

    // ── Identify Controller ───────────────────────────────────────────────────

    /// Issue Identify Controller (CNS=0x01) and return SANICAP bits [2:0].
    pub fn nvme_identify_sanitize_caps(ctrl_path: &str) -> Result<u8, WipeError> {
        let file = open_ctrl(ctrl_path)?;
        let fd = file.as_raw_fd();

        // Allocate 4096-byte Identify Controller data structure (NVMe 1.4 §5.15.2)
        let mut data = vec![0u8; 4096];

        let mut cmd = NvmePassthruCmd {
            opcode: NVME_ADMIN_IDENTIFY,
            nsid: 0,
            cdw10: CNS_CONTROLLER,
            addr: data.as_mut_ptr() as u64,
            data_len: data.len() as u32,
            timeout_ms: 10_000,
            ..Default::default()
        };

        execute_admin_cmd(fd, &mut cmd)?;

        // SANICAP is at bytes 328–331 (offset 328, 4 bytes, little-endian)
        // We only need bits [2:0]
        let sanicap = data[328] & 0x07;
        Ok(sanicap)
    }

    // ── Sanitize ─────────────────────────────────────────────────────────────

    /// Issue the NVMe Sanitize command (opcode 0x84).
    ///
    /// CDW10 layout:
    ///   bits[2:0]  SANACT  — sanitize action
    ///   bit[3]     AUSE    — allow unrestricted sanitize exit (always 0 for forensics)
    ///   bits[7:4]  OWPASS  — overwrite pass count (0 = 16 passes)
    ///   bit[8]     OIPBP   — overwrite invert pattern between passes
    ///   bit[9]     NODAS   — no deallocate after sanitize (0 = deallocate)
    pub fn nvme_sanitize(
        ctrl_path: &str,
        action: SanitizeAction,
        overwrite_pass_count: u8,
        invert_pattern: bool,
    ) -> Result<(), WipeError> {
        let file = open_ctrl(ctrl_path)?;
        let fd = file.as_raw_fd();

        let sanact: u32 = action as u32;
        let owpass: u32 = (overwrite_pass_count as u32 & 0x0F) << 4;
        let oipbp: u32 = if invert_pattern { 1 << 8 } else { 0 };
        let cdw10 = sanact | owpass | oipbp;

        let mut cmd = NvmePassthruCmd {
            opcode: NVME_ADMIN_SANITIZE,
            nsid: 0xFFFF_FFFF, // all namespaces
            cdw10,
            timeout_ms: 0, // no timeout — erase may take hours
            ..Default::default()
        };

        execute_admin_cmd(fd, &mut cmd)
    }

    // ── Format NVM ───────────────────────────────────────────────────────────

    /// Issue NVMe Format NVM (opcode 0x80).
    ///
    /// CDW10 layout:
    ///   bits[3:0]  LBAF  — LBA format (0 = current default)
    ///   bits[5:4]  MS    — metadata settings (0)
    ///   bits[8:6]  PI    — protection information (0 = no PI)
    ///   bit[9]     PIL   — PI location (0)
    ///   bits[11:9] SES   — secure erase settings
    pub fn nvme_format_nvm(
        ctrl_path: &str,
        lba_format: u8,
        ses: SecureEraseSettings,
    ) -> Result<(), WipeError> {
        let file = open_ctrl(ctrl_path)?;
        let fd = file.as_raw_fd();

        let cdw10: u32 = (lba_format as u32 & 0x0F) | ((ses as u32) << 9);

        let mut cmd = NvmePassthruCmd {
            opcode: NVME_ADMIN_FORMAT_NVM,
            nsid: 0xFFFF_FFFF, // format all namespaces
            cdw10,
            timeout_ms: 4 * 3600 * 1000, // 4 hours
            ..Default::default()
        };

        execute_admin_cmd(fd, &mut cmd)
    }

    // ── Sanitize Status log polling ───────────────────────────────────────────

    /// Poll the Sanitize Status log page (0x81) until erase completes or fails.
    ///
    /// The log page layout (NVMe 1.4 §5.14.1.18):
    ///   bytes 0–1:  SPROG  — sanitize progress (0–65535, linear)
    ///   bytes 2–3:  SSTAT  — sanitize status
    ///   bytes 4–7:  SCDW10 — CDW10 of last sanitize
    ///   bytes 8–11: ETUS   — estimated time (overwrite, no deallocate)
    ///   bytes 12–15: ETBES — estimated time (block erase, no deallocate)
    ///   bytes 16–19: ETCES — estimated time (crypto erase, no deallocate)
    pub fn wait_for_sanitize_completion(ctrl_path: &str) -> Result<(), WipeError> {
        log::info!("Waiting for NVMe Sanitize to complete…");

        let poll_interval = std::time::Duration::from_secs(5);

        loop {
            let status = nvme_get_sanitize_status(ctrl_path)?;

            match status {
                SANITIZE_STATUS_IDLE => {
                    // Drive reports idle — erase may not have started yet on first poll,
                    // or completed instantly (some NVMe crypto-erase drives are fast).
                    log::debug!("Sanitize status: IDLE");
                    return Ok(());
                }
                SANITIZE_STATUS_SUCCEEDED => {
                    log::info!("Sanitize status: SUCCEEDED");
                    return Ok(());
                }
                SANITIZE_STATUS_IN_PROGRESS => {
                    log::debug!("Sanitize status: IN PROGRESS");
                    std::thread::sleep(poll_interval);
                }
                SANITIZE_STATUS_FAILED => {
                    return Err(WipeError::NvmeCommandFailed {
                        status: SANITIZE_STATUS_FAILED as u32,
                        detail: "Sanitize operation reported FAILED status".into(),
                    });
                }
                other => {
                    return Err(WipeError::NvmeCommandFailed {
                        status: other as u32,
                        detail: format!("Unknown sanitize status: {:#06x}", other),
                    });
                }
            }
        }
    }

    fn nvme_get_sanitize_status(ctrl_path: &str) -> Result<u16, WipeError> {
        let file = open_ctrl(ctrl_path)?;
        let fd = file.as_raw_fd();

        // Get Log Page — Sanitize Status (log id 0x81, 32 bytes)
        let mut log_data = [0u8; 32];

        // CDW10: log page identifier[7:0] | NUMDL[31:16]
        //   log id = 0x81
        //   NUMDL = (32/4 - 1) = 7  (number of DWORDs - 1)
        let numdl: u32 = (log_data.len() as u32 / 4).saturating_sub(1);
        let cdw10: u32 = (NVME_LOG_SANITIZE_STATUS as u32) | (numdl << 16);

        let mut cmd = NvmePassthruCmd {
            opcode: NVME_ADMIN_GET_LOG_PAGE,
            nsid: 0xFFFF_FFFF,
            cdw10,
            addr: log_data.as_mut_ptr() as u64,
            data_len: log_data.len() as u32,
            timeout_ms: 10_000,
            ..Default::default()
        };

        execute_admin_cmd(fd, &mut cmd)?;

        // SSTAT is bytes 2–3 (little-endian)
        let sstat = u16::from_le_bytes([log_data[2], log_data[3]]);
        // The status code is the lower byte; upper byte is GLOBAL DATA ERASED
        Ok(sstat & 0x00FF)
    }

    // ── ioctl helper ─────────────────────────────────────────────────────────

    pub fn execute_admin_cmd(fd: c_int, cmd: &mut NvmePassthruCmd) -> Result<(), WipeError> {
        let ret = unsafe { ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd as *mut NvmePassthruCmd) };
        if ret < 0 {
            return Err(WipeError::IoctlFailed(std::io::Error::last_os_error()));
        }

        // NVMe completion status is in cmd.result
        // Lower 8 bits: Status Code; bits [10:8]: Status Code Type
        let sc = cmd.result & 0xFF;
        let sct = (cmd.result >> 8) & 0x07;
        if sct != 0 || sc != 0 {
            return Err(WipeError::NvmeCommandFailed {
                status: cmd.result,
                detail: format!(
                    "Status Code Type {:#03x}, Status Code {:#04x}",
                    sct, sc
                ),
            });
        }

        Ok(())
    }

    fn open_ctrl(ctrl_path: &str) -> Result<std::fs::File, WipeError> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(ctrl_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    WipeError::PermissionDenied
                } else {
                    WipeError::Io(e)
                }
            })
    }
}

// ─── Enumerations used by the public API ─────────────────────────────────────

/// NVMe Sanitize action codes (CDW10 bits [2:0]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SanitizeAction {
    /// Exit Failure Mode (0x01) — not a wipe; reserved for error recovery.
    ExitFailureMode = 0x01,
    /// Block Erase (0x02) — erases all blocks including spare.
    BlockErase = 0x02,
    /// Overwrite (0x03) — software-equivalent multi-pass overwrite.
    Overwrite = 0x03,
    /// Cryptographic Erase (0x04) — destroys the encryption key.
    CryptoErase = 0x04,
}

/// NVMe Format NVM Secure Erase Settings (SES field in CDW10 bits [11:9]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SecureEraseSettings {
    /// No secure erase (0x00) — format only, not forensically sufficient.
    None = 0x00,
    /// User Data Erase (0x01) — all user data locations written.
    UserDataErase = 0x01,
    /// Cryptographic Erase (0x02) — encryption key is changed/deleted.
    CryptoErase = 0x02,
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
