//! `WipeEngine` — the top-level orchestrator.
//!
//! Accepts a device path, auto-detects the device type, selects the correct
//! wiping strategy, and executes it.  All public, method-specific entry points
//! are also exposed here for callers that already know their device type.

pub mod nvme;
pub mod ssd;
pub mod usb;

use std::sync::Arc;

use crate::detect::DeviceDetector;
use crate::error::WipeError;
use crate::types::{DeviceInfo, DeviceType, ProgressCallback, WipeResult, WipeStandard};

#[cfg(target_os = "linux")]
use crate::detect::nvme_ctrl_path;

/// Central orchestrator for forensic drive wiping.
///
/// # Example
/// ```rust,no_run
/// use wipe_algorithm::{WipeEngine, WipeStandard};
///
/// let engine = WipeEngine::open("/dev/sdb").expect("failed to open device");
/// let result = engine.wipe(WipeStandard::Nist80088Purge).expect("wipe failed");
/// println!("{}", result.to_json().unwrap());
/// ```
pub struct WipeEngine {
    pub device: DeviceInfo,
    callback: Option<Arc<ProgressCallback>>,
}

impl WipeEngine {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Open a block device, auto-detect its type, and return a ready engine.
    pub fn open(device_path: &str) -> Result<Self, WipeError> {
        let detector = DeviceDetector::new(device_path)?;
        let device = detector.detect()?;
        log::info!(
            "Device detected: {:?} — {} — {} bytes",
            device.device_type,
            device_path,
            device.size_bytes
        );
        Ok(Self {
            device,
            callback: None,
        })
    }

    /// Create an engine from a pre-populated `DeviceInfo` (e.g. from your own
    /// detection logic).
    pub fn with_device_info(device: DeviceInfo) -> Self {
        Self {
            device,
            callback: None,
        }
    }

    /// Attach a progress callback.  The callback is called periodically during
    /// multi-pass software wipes.  Hardware erases (ATA / NVMe) are opaque to
    /// the host, so only start/end events are fired for those.
    pub fn with_progress_callback<F>(mut self, cb: F) -> Self
    where
        F: Fn(crate::types::ProgressInfo) + Send + Sync + 'static,
    {
        self.callback = Some(Arc::new(cb));
        self
    }

    // ── Primary API ───────────────────────────────────────────────────────────

    /// Wipe the device using the best strategy for its type.
    ///
    /// | Device type | Strategy                                                  |
    /// |-------------|-----------------------------------------------------------|
    /// | USB         | Software overwrite (standard-controlled pass schedule)    |
    /// | SSD (SATA)  | ATA Secure Erase / Enhanced Secure Erase                  |
    /// | NVMe        | NVMe Sanitize (Crypto → Block → Overwrite) or Format NVM |
    /// | HDD         | Software overwrite — ATA Secure Erase if available        |
    /// | Unknown     | Software overwrite (safe fallback)                        |
    pub fn wipe(&self, standard: WipeStandard) -> Result<WipeResult, WipeError> {
        match self.device.device_type {
            DeviceType::Usb => self.wipe_usb(standard),
            DeviceType::Ssd => self.wipe_ssd(standard),
            DeviceType::Nvme => self.wipe_nvme(standard, true),
            DeviceType::Hdd => self.wipe_hdd(standard),
            DeviceType::Unknown => {
                log::warn!("Unknown device type — falling back to software overwrite");
                self.wipe_usb(standard)
            }
        }
    }

    // ── Method-specific entry points ──────────────────────────────────────────

    /// Force a software overwrite wipe regardless of device type.
    ///
    /// Use this for USB flash drives.  NIST 800-88 recommends a single pass
    /// for ATA-attached flash; the `standard` argument controls the full
    /// pass schedule for DoD / Gutmann / custom requirements.
    pub fn wipe_usb(&self, standard: WipeStandard) -> Result<WipeResult, WipeError> {
        let wiper = usb::UsbWiper {
            device: &self.device,
            callback: self.callback.clone(),
        };
        wiper.wipe(&standard)
    }

    /// Perform an ATA Secure Erase on a SATA SSD.
    ///
    /// Uses Enhanced Secure Erase (crypto erase path) when the drive supports
    /// it and the standard is `Nist80088Purge`; otherwise uses normal erase.
    ///
    /// **Requires:** ATA security not frozen.  If frozen, suspend-to-RAM and
    /// retry (some drives unfreeze on resume).
    pub fn wipe_ssd(&self, standard: WipeStandard) -> Result<WipeResult, WipeError> {
        if self.device.device_type == DeviceType::Nvme {
            return Err(WipeError::UnsupportedDevice(
                "NVMe drives must use wipe_nvme(), not wipe_ssd()".into(),
            ));
        }
        let wiper = ssd::SsdWiper {
            device: &self.device,
        };
        wiper.wipe(&standard)
    }

    /// Perform an NVMe Sanitize or Format NVM command.
    ///
    /// `prefer_crypto` — when `true`, Crypto Erase is chosen over Block Erase
    /// if both are supported.  Crypto Erase is faster; Block Erase is more
    /// thorough (suitable for classified media).
    pub fn wipe_nvme(&self, standard: WipeStandard, prefer_crypto: bool) -> Result<WipeResult, WipeError> {
        let ctrl_path = self.nvme_ctrl_path()?;
        let wiper = nvme::NvmeWiper::new(&self.device, ctrl_path);
        wiper.wipe(&standard, prefer_crypto)
    }

    /// Wipe a spinning HDD.
    ///
    /// Attempts ATA Secure Erase first (if supported and not frozen); falls
    /// back to a multi-pass software overwrite.
    pub fn wipe_hdd(&self, standard: WipeStandard) -> Result<WipeResult, WipeError> {
        if self.device.ata_security_supported && !self.device.ata_security_frozen {
            log::info!("HDD: ATA Security supported — attempting ATA Secure Erase");
            let wiper = ssd::SsdWiper {
                device: &self.device,
            };
            match wiper.wipe(&standard) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    log::warn!("ATA Secure Erase failed ({}); falling back to overwrite", e);
                }
            }
        }
        log::info!("HDD: using software overwrite wipe");
        self.wipe_usb(standard)
    }

    // ── Device info accessors ─────────────────────────────────────────────────

    /// Return a reference to the detected device metadata.
    pub fn device_info(&self) -> &DeviceInfo {
        &self.device
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn nvme_ctrl_path(&self) -> Result<String, WipeError> {
        #[cfg(target_os = "linux")]
        {
            use std::path::Path;
            let dev_name = Path::new(&self.device.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            return Ok(nvme_ctrl_path(dev_name));
        }

        #[cfg(not(target_os = "linux"))]
        return Err(WipeError::PlatformNotSupported);
    }
}
