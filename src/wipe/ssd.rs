//! ATA Secure Erase support for SATA SSDs and HDDs.
//!
//! Implements the ATA Security Feature Set via the Linux SG_IO passthrough
//! interface (SCSI Generic driver).  Each command is encoded as a 16-byte
//! ATA-PASS-THROUGH(16) CDB (SCSI opcode 0x85) and delivered via ioctl
//! `SG_IO` (0x2285).
//!
//! ## Procedure
//! 1. `IDENTIFY DEVICE` (0xEC) — parse security status word (128).
//! 2. Reject if security state is **frozen**.
//! 3. `SECURITY SET PASSWORD` (0xF1) — set a temporary master password.
//! 4. `SECURITY ERASE PREPARE` (0xF3) — mandatory unlock before erase.
//! 5. `SECURITY ERASE UNIT` (0xF4) — execute erase (enhanced if supported).
//!
//! After a successful Secure Erase the drive resets its security state and
//! the temporary password is invalidated.
//!
//! **Windows stub** — Windows requires `IOCTL_ATA_PASS_THROUGH_DIRECT`
//! (`DeviceIoControl`).  The structure mirrors `SG_IO` semantically.
//! Implement `ssd_wipe_windows` when Windows support is needed.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::WipeError;
use crate::types::{DeviceInfo, WipeMethod, WipeResult, WipeStandard};

/// Temporary password written to the drive before erasing.
/// It is overwritten by the erase and is never user-visible.
/// Exactly 32 bytes as required by ACS-3 §7.63.3 (password field).
const TEMP_PASSWORD: &[u8; 32] = b"FORENSIC_WIPE_TEMP_0000000000000";

pub struct SsdWiper<'a> {
    pub device: &'a DeviceInfo,
}

impl<'a> SsdWiper<'a> {
    /// Perform an ATA Secure Erase.
    ///
    /// Uses `Enhanced Secure Erase` when the drive supports it (the enhanced
    /// path rewrites every user-data location with a vendor-defined pattern and
    /// is equivalent to NIST 800-88 Purge); otherwise falls back to the normal
    /// erase (Clear-equivalent).
    pub fn wipe(&self, standard: &WipeStandard) -> Result<WipeResult, WipeError> {
        #[cfg(target_os = "linux")]
        return self.wipe_linux(standard);

        #[cfg(target_os = "windows")]
        return Err(WipeError::PlatformNotSupported);

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        return Err(WipeError::PlatformNotSupported);
    }

    /// Query ATA security status for the device path.
    /// Returns `(supported, frozen, enhanced_supported)`.
    pub fn identify_security_status(device_path: &str) -> Result<(bool, bool, bool), WipeError> {
        #[cfg(target_os = "linux")]
        return linux::ata_identify_security(device_path);

        #[cfg(not(target_os = "linux"))]
        return Ok((false, false, false));
    }
}

// ─── Linux implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
impl<'a> SsdWiper<'a> {
    fn wipe_linux(&self, standard: &WipeStandard) -> Result<WipeResult, WipeError> {
        let started_at = unix_now();
        let path = &self.device.path;

        if !self.device.ata_security_supported {
            return Err(WipeError::AtaSecurityNotSupported);
        }
        if self.device.ata_security_frozen {
            return Err(WipeError::DeviceSecurityFrozen);
        }

        let use_enhanced = self.device.ata_enhanced_erase_supported
            && matches!(standard, WipeStandard::Nist80088Purge);

        let method = if use_enhanced {
            WipeMethod::AtaEnhancedSecureErase
        } else {
            WipeMethod::AtaSecureErase
        };

        log::info!(
            "ATA Secure Erase: {} — {}",
            path,
            if use_enhanced { "ENHANCED" } else { "NORMAL" }
        );

        // Step 1 — set master password
        linux::ata_security_set_password(path, TEMP_PASSWORD)?;
        log::debug!("ATA SECURITY SET PASSWORD issued");

        // Step 2 — mandatory prepare command
        linux::ata_security_erase_prepare(path)?;
        log::debug!("ATA SECURITY ERASE PREPARE issued");

        // Step 3 — execute erase (may take several minutes to hours)
        linux::ata_security_erase_unit(path, use_enhanced)?;
        log::info!("ATA SECURITY ERASE UNIT completed successfully");

        Ok(WipeResult {
            success: true,
            device_path: path.clone(),
            standard_requested: standard.clone(),
            method_used: method,
            bytes_processed: self.device.size_bytes,
            passes_completed: 1,
            verified: false, // hardware-internal; no read-back needed
            started_at_unix: started_at,
            completed_at_unix: unix_now(),
            messages: vec![
                "ATA Secure Erase completed; drive security state has been reset.".into(),
            ],
        })
    }
}

// ─── Linux SG_IO / ATA passthrough primitives ────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use libc::{c_int, c_void, ioctl};
    use std::os::unix::io::AsRawFd;

    // ── Constants ─────────────────────────────────────────────────────────────

    const SG_IO: libc::c_ulong = 0x2285;
    const SG_DXFER_NONE: i32 = -1;
    const SG_DXFER_TO_DEV: i32 = -2;
    const SG_DXFER_FROM_DEV: i32 = -3;

    // ATA-PASS-THROUGH(16) SCSI opcode
    const ATA_16: u8 = 0x85;

    // ATA protocols encoded in CDB[1] bits [4:1]
    const PROTO_NON_DATA: u8 = 3 << 1;
    const PROTO_PIO_IN: u8 = 4 << 1;
    const PROTO_PIO_OUT: u8 = 5 << 1;

    // CDB[2] flags
    const T_DIR_TO_DEV: u8 = 0x00; // transfer to device
    const T_DIR_FROM_DEV: u8 = 0x08; // transfer from device
    const BYTE_BLOCK: u8 = 0x04; // sector-count unit
    const T_LENGTH_SECTOR_COUNT: u8 = 0x02; // T_LENGTH uses sector count reg

    // ATA commands
    const CMD_IDENTIFY_DEVICE: u8 = 0xEC;
    const CMD_SECURITY_SET_PASSWORD: u8 = 0xF1;
    const CMD_SECURITY_ERASE_PREPARE: u8 = 0xF3;
    const CMD_SECURITY_ERASE_UNIT: u8 = 0xF4;

    // Timeout for the slow SECURITY ERASE UNIT command (4 hours in ms)
    const ERASE_TIMEOUT_MS: u32 = 4 * 3600 * 1000;
    const FAST_TIMEOUT_MS: u32 = 30_000;

    // ── C-layout structures ───────────────────────────────────────────────────

    /// `struct sg_io_hdr` from `<scsi/sg.h>` (64-bit layout).
    #[repr(C)]
    struct SgIoHdr {
        interface_id: c_int,
        dxfer_direction: c_int,
        cmd_len: u8,
        mx_sb_len: u8,
        iovec_count: u16,
        dxfer_len: u32,
        dxferp: *mut c_void,
        cmdp: *const u8,
        sbp: *mut c_void,
        timeout: u32,
        flags: u32,
        pack_id: c_int,
        usr_ptr: *mut c_void,
        status: u8,
        masked_status: u8,
        msg_status: u8,
        sb_len_wr: u8,
        host_status: u16,
        driver_status: u16,
        resid: c_int,
        duration: u32,
        info: u32,
    }

    // ── Public helpers ────────────────────────────────────────────────────────

    /// Issue ATA IDENTIFY DEVICE and return security status.
    /// Returns `(supported, frozen, enhanced_supported)`.
    pub fn ata_identify_security(path: &str) -> Result<(bool, bool, bool), WipeError> {
        let file = open_rw(path)?;
        let fd = file.as_raw_fd();

        let mut data = [0u8; 512];
        ata_pio_in(
            fd,
            CMD_IDENTIFY_DEVICE,
            0, // features
            1, // sector count
            &mut data,
            FAST_TIMEOUT_MS,
        )?;

        // Word 128 (bytes 256–257, little-endian) = security status
        let security_word = u16::from_le_bytes([data[256], data[257]]);
        let supported = security_word & (1 << 0) != 0;
        let frozen = security_word & (1 << 3) != 0;
        let enhanced = security_word & (1 << 5) != 0;

        Ok((supported, frozen, enhanced))
    }

    /// ATA SECURITY SET PASSWORD (0xF1)
    pub fn ata_security_set_password(path: &str, password: &[u8; 32]) -> Result<(), WipeError> {
        let file = open_rw(path)?;
        let fd = file.as_raw_fd();

        // 512-byte password sector per ACS-3 §7.63.3
        // Byte 0–1: Control word (0x0000 = user password, normal capability)
        // Byte 2–33: Password (32 bytes, zero-padded)
        let mut sector = [0u8; 512];
        // Bytes 0–1: Identifier = 0 (user password), Master PW capability = 0 (high)
        sector[0] = 0x00;
        sector[1] = 0x00;
        sector[2..34].copy_from_slice(password);

        ata_pio_out(
            fd,
            CMD_SECURITY_SET_PASSWORD,
            0,
            1,
            &sector,
            FAST_TIMEOUT_MS,
        )?;
        Ok(())
    }

    /// ATA SECURITY ERASE PREPARE (0xF3) — must precede ERASE UNIT.
    pub fn ata_security_erase_prepare(path: &str) -> Result<(), WipeError> {
        let file = open_rw(path)?;
        let fd = file.as_raw_fd();
        ata_non_data(fd, CMD_SECURITY_ERASE_PREPARE, 0, FAST_TIMEOUT_MS)?;
        Ok(())
    }

    /// ATA SECURITY ERASE UNIT (0xF4).
    ///
    /// `enhanced = true` sets bit 1 of the Features register, requesting the
    /// vendor-defined Enhanced Secure Erase (crypto erase equivalent).
    pub fn ata_security_erase_unit(path: &str, enhanced: bool) -> Result<(), WipeError> {
        let file = open_rw(path)?;
        let fd = file.as_raw_fd();

        // Features register: bit 0 = IDENTIFIER (0 = user password),
        //                    bit 1 = ENHANCED ERASE.
        let features: u8 = if enhanced { 0x02 } else { 0x00 };

        // Password sector — same layout as SET PASSWORD
        let mut sector = [0u8; 512];
        sector[2..34].copy_from_slice(super::TEMP_PASSWORD);

        ata_pio_out(
            fd,
            CMD_SECURITY_ERASE_UNIT,
            features,
            1,
            &sector,
            ERASE_TIMEOUT_MS,
        )?;
        Ok(())
    }

    // ── SG_IO ATA passthrough builders ───────────────────────────────────────

    /// Non-data ATA command (no DMA/PIO transfer).
    fn ata_non_data(
        fd: c_int,
        command: u8,
        features: u8,
        timeout_ms: u32,
    ) -> Result<(), WipeError> {
        let cdb = build_cdb_non_data(command, features);
        let mut sense = [0u8; 32];
        let mut hdr = SgIoHdr {
            interface_id: b'S' as c_int,
            dxfer_direction: SG_DXFER_NONE,
            cmd_len: 16,
            mx_sb_len: sense.len() as u8,
            iovec_count: 0,
            dxfer_len: 0,
            dxferp: std::ptr::null_mut(),
            cmdp: cdb.as_ptr(),
            sbp: sense.as_mut_ptr() as *mut c_void,
            timeout: timeout_ms,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };
        execute_sg_io(fd, &mut hdr, &sense)
    }

    /// PIO data-in ATA command (device → host).
    fn ata_pio_in(
        fd: c_int,
        command: u8,
        features: u8,
        sectors: u8,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<(), WipeError> {
        let cdb = build_cdb_pio_in(command, features, sectors);
        let mut sense = [0u8; 32];
        let mut hdr = SgIoHdr {
            interface_id: b'S' as c_int,
            dxfer_direction: SG_DXFER_FROM_DEV,
            cmd_len: 16,
            mx_sb_len: sense.len() as u8,
            iovec_count: 0,
            dxfer_len: buf.len() as u32,
            dxferp: buf.as_mut_ptr() as *mut c_void,
            cmdp: cdb.as_ptr(),
            sbp: sense.as_mut_ptr() as *mut c_void,
            timeout: timeout_ms,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };
        execute_sg_io(fd, &mut hdr, &sense)
    }

    /// PIO data-out ATA command (host → device).
    fn ata_pio_out(
        fd: c_int,
        command: u8,
        features: u8,
        sectors: u8,
        buf: &[u8],
        timeout_ms: u32,
    ) -> Result<(), WipeError> {
        let cdb = build_cdb_pio_out(command, features, sectors);
        let mut sense = [0u8; 32];
        let buf_ptr = buf.as_ptr() as *mut c_void;
        let mut hdr = SgIoHdr {
            interface_id: b'S' as c_int,
            dxfer_direction: SG_DXFER_TO_DEV,
            cmd_len: 16,
            mx_sb_len: sense.len() as u8,
            iovec_count: 0,
            dxfer_len: buf.len() as u32,
            dxferp: buf_ptr,
            cmdp: cdb.as_ptr(),
            sbp: sense.as_mut_ptr() as *mut c_void,
            timeout: timeout_ms,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };
        execute_sg_io(fd, &mut hdr, &sense)
    }

    // ── CDB builders for ATA-PASS-THROUGH(16) ────────────────────────────────
    //
    // CDB layout (16 bytes):
    //   [0]  = 0x85  (ATA-PASS-THROUGH(16) SCSI opcode)
    //   [1]  = (protocol << 1) | EXTEND
    //   [2]  = T_DIR | BYTE_BLOCK | T_LENGTH
    //   [3]  = features[7:0]
    //   [4]  = features[15:8]  (EXTEND=0 → 0)
    //   [5]  = sector_count[7:0]
    //   [6]  = sector_count[15:8] (EXTEND=0 → 0)
    //   [7]  = lba_low[7:0]    (0)
    //   [8]  = lba_low[15:8]   (0)
    //   [9]  = lba_mid[7:0]    (0)
    //   [10] = lba_mid[15:8]   (0)
    //   [11] = lba_high[7:0]   (0)
    //   [12] = lba_high[15:8]  (0)
    //   [13] = device          (0)
    //   [14] = command
    //   [15] = control         (0)

    fn build_cdb_non_data(command: u8, features: u8) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = ATA_16;
        cdb[1] = PROTO_NON_DATA;
        cdb[2] = 0x00; // no data transfer
        cdb[3] = features;
        cdb[14] = command;
        cdb
    }

    fn build_cdb_pio_in(command: u8, features: u8, sectors: u8) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = ATA_16;
        cdb[1] = PROTO_PIO_IN;
        cdb[2] = T_DIR_FROM_DEV | BYTE_BLOCK | T_LENGTH_SECTOR_COUNT;
        cdb[3] = features;
        cdb[5] = sectors;
        cdb[14] = command;
        cdb
    }

    fn build_cdb_pio_out(command: u8, features: u8, sectors: u8) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = ATA_16;
        cdb[1] = PROTO_PIO_OUT;
        cdb[2] = T_DIR_TO_DEV | BYTE_BLOCK | T_LENGTH_SECTOR_COUNT;
        cdb[3] = features;
        cdb[5] = sectors;
        cdb[14] = command;
        cdb
    }

    // ── ioctl execution and error checking ────────────────────────────────────

    fn execute_sg_io(fd: c_int, hdr: &mut SgIoHdr, sense: &[u8]) -> Result<(), WipeError> {
        let ret = unsafe { ioctl(fd, SG_IO, hdr as *mut SgIoHdr) };
        if ret < 0 {
            return Err(WipeError::IoctlFailed(std::io::Error::last_os_error()));
        }

        // Check SCSI status — 0x02 = CHECK CONDITION
        if hdr.status == 0x02 {
            let sense_key = sense[2] & 0x0F;
            let asc = sense[12];
            let ascq = sense[13];
            // ATA device error is reported in the sense data descriptor
            // (sense key 0x00 with asc=0x00 is usually OK for ATA passthrough)
            if sense_key != 0x00 {
                return Err(WipeError::AtaCheckCondition {
                    sense_key,
                    asc,
                    ascq,
                });
            }
        }

        if hdr.host_status != 0 {
            return Err(WipeError::AtaSecureEraseFailed(format!(
                "SG host_status = {:#06x}",
                hdr.host_status
            )));
        }

        Ok(())
    }

    fn open_rw(path: &str) -> Result<std::fs::File, WipeError> {
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
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
