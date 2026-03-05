use thiserror::Error;

/// All errors that can be produced by the wipe algorithm library.
#[derive(Debug, Error)]
pub enum WipeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Device not found: {path}")]
    DeviceNotFound { path: String },

    #[error("Permission denied — root/administrator privileges are required to access raw devices")]
    PermissionDenied,

    #[error("Unsupported device type: {0}")]
    UnsupportedDevice(String),

    #[error("ATA Secure Erase failed: {0}")]
    AtaSecureEraseFailed(String),

    #[error("NVMe command failed with status {status:#06x}: {detail}")]
    NvmeCommandFailed { status: u32, detail: String },

    #[error("Device ATA security state is frozen — suspend the system briefly to unfreeze, then retry")]
    DeviceSecurityFrozen,

    #[error("ioctl failed: {0}")]
    IoctlFailed(std::io::Error),

    #[error("Verification failed at byte offset {offset}: expected {expected:#04x}, found {found:#04x}")]
    VerificationFailed { offset: u64, expected: u8, found: u8 },

    #[error("Invalid device path '{path}': {reason}")]
    InvalidDevicePath { path: String, reason: String },

    #[error("Wipe aborted: {0}")]
    WipeAborted(String),

    #[error("This device does not support ATA Security features (IDENTIFY DEVICE word 82 not set)")]
    AtaSecurityNotSupported,

    #[error("This device does not support the NVMe Sanitize command (SANICAP = 0)")]
    NvmeSanitizeNotSupported,

    #[error("This device does not support NVMe Format NVM")]
    NvmeFormatNotSupported,

    #[error("ATA command returned CHECK CONDITION; sense key {sense_key:#04x}, asc {asc:#04x}, ascq {ascq:#04x}")]
    AtaCheckCondition { sense_key: u8, asc: u8, ascq: u8 },

    #[error("Failed to read device size — the path may not be a block device")]
    DeviceSizeUnknown,

    #[error("This operation is not supported on this operating system")]
    PlatformNotSupported,

    #[error("Device detection failed: {0}")]
    DetectionFailed(String),
}
