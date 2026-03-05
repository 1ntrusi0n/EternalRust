//! Device detection — determines whether a block device is a USB drive, SATA SSD,
//! NVMe drive, or spinning HDD, and collects the metadata required to choose the
//! correct wiping strategy.
//!
//! **Linux** — reads from `/sys/block/<dev>/` (sysfs) and issues ATA IDENTIFY DEVICE /
//! NVMe Identify Controller commands through the kernel's passthrough ioctls.
//!
//! **Windows** — uses `DeviceIoControl` with `IOCTL_STORAGE_QUERY_PROPERTY`.

use crate::error::WipeError;
use crate::types::{DeviceInfo, DeviceType};

/// Entry point for device detection.
pub struct DeviceDetector {
    /// The raw block-device path supplied by the caller.
    pub path: String,
}

impl DeviceDetector {
    /// Create a detector for the given block device.
    ///
    /// Returns `Err(WipeError::DeviceNotFound)` if the path does not exist.
    pub fn new(path: &str) -> Result<Self, WipeError> {
        if !std::path::Path::new(path).exists() {
            return Err(WipeError::DeviceNotFound {
                path: path.to_string(),
            });
        }
        Ok(Self {
            path: path.to_string(),
        })
    }

    /// Detect device type and collect metadata.
    pub fn detect(&self) -> Result<DeviceInfo, WipeError> {
        #[cfg(target_os = "linux")]
        return self.detect_linux();

        #[cfg(target_os = "windows")]
        return self.detect_windows();

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        return Err(WipeError::PlatformNotSupported);
    }
}

// ─── Linux implementation ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
impl DeviceDetector {
    fn detect_linux(&self) -> Result<DeviceInfo, WipeError> {
        let dev_name = self.device_name()?;

        let device_type = self.classify_device(&dev_name)?;
        let size_bytes = self.read_device_size(&dev_name)?;
        let sector_size = self.read_sector_size(&dev_name)?;
        let removable = self.read_removable(&dev_name);
        let (model, serial) = self.read_model_serial(&dev_name);

        let (ata_security_supported, ata_security_frozen, ata_enhanced_erase_supported) =
            if device_type == DeviceType::Ssd || device_type == DeviceType::Hdd {
                self.query_ata_security(&dev_name).unwrap_or((false, false, false))
            } else {
                (false, false, false)
            };

        let nvme_sanitize_caps = if device_type == DeviceType::Nvme {
            self.query_nvme_sanitize_caps(&dev_name).unwrap_or(0)
        } else {
            0
        };

        Ok(DeviceInfo {
            path: self.path.clone(),
            device_type,
            size_bytes,
            model,
            serial,
            removable,
            sector_size,
            ata_security_supported,
            ata_security_frozen,
            ata_enhanced_erase_supported,
            nvme_sanitize_caps,
        })
    }

    /// Extract the bare device name from the path (e.g. "sdb" from "/dev/sdb").
    fn device_name(&self) -> Result<String, WipeError> {
        std::path::Path::new(&self.path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| WipeError::InvalidDevicePath {
                path: self.path.clone(),
                reason: "cannot extract device name component".into(),
            })
    }

    /// Classify the device by inspecting sysfs attributes.
    fn classify_device(&self, dev_name: &str) -> Result<DeviceType, WipeError> {
        // NVMe devices always appear as nvme<ctrl>n<ns>
        if dev_name.starts_with("nvme") {
            return Ok(DeviceType::Nvme);
        }

        // USB: the sysfs device symlink passes through a "usb" component.
        if self.is_usb(dev_name) {
            return Ok(DeviceType::Usb);
        }

        // SSD vs HDD: `queue/rotational` = 0 for flash.
        let rotational = self.read_sysfs_u32(dev_name, "queue/rotational").unwrap_or(1);
        if rotational == 0 {
            Ok(DeviceType::Ssd)
        } else {
            Ok(DeviceType::Hdd)
        }
    }

    /// Returns `true` if the block device is connected over USB.
    fn is_usb(&self, dev_name: &str) -> bool {
        let link_path = format!("/sys/block/{}/device", dev_name);
        // The symlink target for USB storage passes through ".../usbN/..."
        std::fs::read_link(&link_path)
            .map(|p| p.to_string_lossy().contains("usb"))
            .unwrap_or(false)
    }

    /// Read a decimal integer from a sysfs attribute file.
    fn read_sysfs_u32(&self, dev_name: &str, attr: &str) -> Option<u32> {
        let path = format!("/sys/block/{}/{}", dev_name, attr);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Read a string from a sysfs attribute file, trimming whitespace.
    fn read_sysfs_string(&self, dev_name: &str, attr: &str) -> Option<String> {
        let path = format!("/sys/block/{}/{}", dev_name, attr);
        std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Obtain the device size in bytes via the `BLKGETSIZE64` ioctl.
    fn read_device_size(&self, _dev_name: &str) -> Result<u64, WipeError> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    WipeError::PermissionDenied
                } else {
                    WipeError::Io(e)
                }
            })?;

        let mut size: u64 = 0;
        // BLKGETSIZE64 = _IOR(0x12, 114, u64) = 0x80081272
        const BLKGETSIZE64: libc::c_ulong = 0x80081272;
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64, &mut size) };
        if ret < 0 {
            return Err(WipeError::IoctlFailed(std::io::Error::last_os_error()));
        }
        Ok(size)
    }

    /// Logical sector size from sysfs, falling back to 512.
    fn read_sector_size(&self, dev_name: &str) -> Result<u32, WipeError> {
        Ok(self
            .read_sysfs_u32(dev_name, "queue/logical_block_size")
            .unwrap_or(512))
    }

    /// Removable flag from sysfs.
    fn read_removable(&self, dev_name: &str) -> bool {
        self.read_sysfs_u32(dev_name, "removable")
            .map(|v| v != 0)
            .unwrap_or(false)
    }

    /// Model and serial from sysfs `device/model` and `device/serial`.
    fn read_model_serial(&self, dev_name: &str) -> (Option<String>, Option<String>) {
        let model = self.read_sysfs_string(dev_name, "device/model");
        let serial = self.read_sysfs_string(dev_name, "device/serial");
        (model, serial)
    }

    /// Issue an ATA IDENTIFY DEVICE command via SG_IO and parse the security
    /// feature word (128) to determine: supported, frozen, enhanced.
    fn query_ata_security(
        &self,
        _dev_name: &str,
    ) -> Result<(bool, bool, bool), WipeError> {
        use crate::wipe::ssd::SsdWiper;
        SsdWiper::identify_security_status(&self.path)
    }

    /// Issue an NVMe Identify Controller command and return the SANICAP byte.
    fn query_nvme_sanitize_caps(&self, dev_name: &str) -> Result<u8, WipeError> {
        use crate::wipe::nvme::NvmeWiper;
        // The admin ioctl is sent to the controller device, not the namespace.
        let ctrl_path = nvme_ctrl_path(dev_name);
        NvmeWiper::identify_sanitize_caps(&ctrl_path)
    }
}

/// Derive the NVMe controller device path from a namespace device name.
/// e.g. "nvme0n1" → "/dev/nvme0", "nvme1n2" → "/dev/nvme1"
#[cfg(target_os = "linux")]
pub fn nvme_ctrl_path(dev_name: &str) -> String {
    // Strip the "n<namespace>" suffix
    let ctrl = dev_name
        .split('n')
        .next()
        .unwrap_or(dev_name);
    format!("/dev/{}", ctrl)
}

// ─── Windows implementation ──────────────────────────────────────────────────

// ── Windows stubs ─────────────────────────────────────────────────────────────
//
// Full Windows implementation requires `DeviceIoControl` with:
//   - `IOCTL_STORAGE_QUERY_PROPERTY` (StorageDeviceProperty) → bus type, model, serial
//   - `IOCTL_DISK_GET_LENGTH_INFO`                           → size in bytes
//   - `IOCTL_ATA_PASS_THROUGH_DIRECT`                       → ATA security status
//   - `IOCTL_STORAGE_PROTOCOL_COMMAND`                       → NVMe Identify/Sanitize
//
// The windows-sys feature set needed:
//   Win32_Storage_FileSystem, Win32_System_Ioctl, Win32_Foundation, Win32_System_IO
//
// Uncomment and implement once Windows support is prioritised.

#[cfg(target_os = "windows")]
impl DeviceDetector {
    fn detect_windows(&self) -> Result<DeviceInfo, WipeError> {
        // Placeholder — returns Unknown type with zeroed fields until the full
        // Windows DeviceIoControl implementation is added.
        log::warn!(
            "Windows device detection is not yet fully implemented; \
             returning Unknown device type for {}",
            self.path
        );
        Ok(DeviceInfo {
            path: self.path.clone(),
            device_type: DeviceType::Unknown,
            size_bytes: 0,
            model: None,
            serial: None,
            removable: false,
            sector_size: 512,
            ata_security_supported: false,
            ata_security_frozen: false,
            ata_enhanced_erase_supported: false,
            nvme_sanitize_caps: 0,
        })
    }
}
