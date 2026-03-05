use serde::{Deserialize, Serialize};

/// The class of storage device, used to select the correct wiping strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// USB flash drive (or any USB-attached storage).
    /// Always wiped via multi-pass software overwrite.
    Usb,

    /// SATA Solid State Drive.
    /// Preferably wiped via ATA Secure Erase / Enhanced Secure Erase.
    Ssd,

    /// NVMe M.2 or PCIe drive.
    /// Wiped via NVMe Sanitize or Format NVM admin commands.
    Nvme,

    /// Traditional spinning Hard Disk Drive.
    /// Wiped via multi-pass software overwrite (ATA Secure Erase also supported).
    Hdd,

    /// Could not reliably determine device type.
    Unknown,
}

/// The wiping standard to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeStandard {
    /// **NIST SP 800-88 Rev 1 — Clear**
    ///
    /// Single overwrite pass with a fixed pattern (0x00).
    /// Suitable for ATA drives where Secure Erase is unavailable.
    Nist80088Clear,

    /// **NIST SP 800-88 Rev 1 — Purge**
    ///
    /// Uses the drive's built-in hardware erase command (ATA Secure Erase /
    /// NVMe Sanitize). Falls back to `Nist80088Clear` if hardware erase is
    /// unavailable.  This is the recommended standard for SSDs and NVMe drives.
    Nist80088Purge,

    /// **DoD 5220.22-M (3-pass)**
    ///
    /// Pass 1: 0x00  |  Pass 2: 0xFF  |  Pass 3: random  |  Verify pass 3.
    DoD522022M,

    /// **DoD 5220.22-M ECE (7-pass)**
    ///
    /// Extended Clearing Erasure used for top-secret classified media.
    DoD522022MECE,

    /// **Gutmann 35-pass**
    ///
    /// Not recommended for modern flash/SSD media; included for legacy
    /// magnetic media compliance.
    Gutmann,

    /// Fully custom pass schedule defined by the caller.
    Custom { passes: Vec<WipePass> },
}

/// A single pass in a software overwrite sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipePass {
    /// Overwrite every byte with a constant value.
    Fixed(u8),
    /// Overwrite every byte with cryptographically-seeded random data.
    Random,
    /// Overwrite every byte with the bitwise complement of the previous pass.
    Complement,
}

/// All information the library has gathered about a block device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Canonical block-device path (`/dev/sdb`, `/dev/nvme0n1`, `\\.\PhysicalDrive1`).
    pub path: String,

    /// Detected hardware category.
    pub device_type: DeviceType,

    /// Logical size of the device in bytes.
    pub size_bytes: u64,

    /// Drive model string (from IDENTIFY DEVICE / Identify Controller).
    pub model: Option<String>,

    /// Drive serial number.
    pub serial: Option<String>,

    /// Whether the OS reports the device as removable.
    pub removable: bool,

    /// Logical sector size in bytes (typically 512 or 4096).
    pub sector_size: u32,

    /// True if the ATA Security Feature Set is supported (IDENTIFY DEVICE word 82).
    pub ata_security_supported: bool,

    /// True if the ATA security state is currently frozen (erase will be blocked).
    pub ata_security_frozen: bool,

    /// True if Enhanced Secure Erase is supported (faster crypto erase path).
    pub ata_enhanced_erase_supported: bool,

    /// Bitmask from NVMe Identify Controller SANICAP field:
    /// bit 0 = Crypto Erase, bit 1 = Block Erase, bit 2 = Overwrite.
    pub nvme_sanitize_caps: u8,
}

impl DeviceInfo {
    pub fn nvme_crypto_erase_supported(&self) -> bool {
        self.nvme_sanitize_caps & 0x01 != 0
    }
    pub fn nvme_block_erase_supported(&self) -> bool {
        self.nvme_sanitize_caps & 0x02 != 0
    }
    pub fn nvme_overwrite_supported(&self) -> bool {
        self.nvme_sanitize_caps & 0x04 != 0
    }
}

/// The physical mechanism used to wipe a drive — included in the audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WipeMethod {
    /// Multi-pass software overwrite via direct block writes.
    SoftwareOverwrite { passes: Vec<WipePass> },
    /// ATA SECURITY ERASE UNIT command (normal).
    AtaSecureErase,
    /// ATA SECURITY ERASE UNIT command (enhanced / crypto erase path).
    AtaEnhancedSecureErase,
    /// NVMe Sanitize — Cryptographic Erase action (0x4).
    NvmeSanitizeCryptoErase,
    /// NVMe Sanitize — Block Erase action (0x2).
    NvmeSanitizeBlockErase,
    /// NVMe Sanitize — Overwrite action (0x3).
    NvmeSanitizeOverwrite { pass_count: u8 },
    /// NVMe Format NVM with Secure Erase Setting = User Data Erase (0x1).
    NvmeFormatUserDataErase,
    /// NVMe Format NVM with Secure Erase Setting = Cryptographic Erase (0x2).
    NvmeFormatCryptoErase,
}

/// Passed to the optional progress callback on every reporting interval.
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    /// Bytes written / verified so far in the current pass.
    pub bytes_done: u64,
    /// Total bytes in the device.
    pub total_bytes: u64,
    /// 1-based index of the currently executing pass.
    pub current_pass: u32,
    /// Total number of passes in the schedule.
    pub total_passes: u32,
    /// Overall completion percentage (0.0 – 100.0).
    pub percentage: f64,
    /// Human-readable description of the active operation.
    pub description: String,
}

/// Caller-supplied progress callback type.
///
/// Use `Arc<dyn Fn(ProgressInfo) + Send + Sync>` internally to allow
/// sharing across threads.
pub type ProgressCallback = dyn Fn(ProgressInfo) + Send + Sync;

/// Full audit record returned after a wipe operation completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeResult {
    /// `true` if all passes succeeded and (where applicable) verification passed.
    pub success: bool,

    /// Device path that was wiped.
    pub device_path: String,

    /// Standard requested by the caller.
    pub standard_requested: WipeStandard,

    /// Actual wiping mechanism applied.
    pub method_used: WipeMethod,

    /// Total bytes written across all passes.
    pub bytes_processed: u64,

    /// Number of overwrite passes completed.
    pub passes_completed: u32,

    /// Whether a read-back verification pass was performed and succeeded.
    pub verified: bool,

    /// Unix timestamp (seconds) when the wipe started.
    pub started_at_unix: i64,

    /// Unix timestamp (seconds) when the wipe finished.
    pub completed_at_unix: i64,

    /// Informational messages / warnings accumulated during the operation.
    pub messages: Vec<String>,
}

impl WipeResult {
    /// Duration of the wipe in seconds.
    pub fn duration_secs(&self) -> i64 {
        self.completed_at_unix - self.started_at_unix
    }

    /// Serialise to a pretty-printed JSON string suitable for inclusion in
    /// a chain-of-custody document.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
