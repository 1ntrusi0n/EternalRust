# EternalRust 🧼💾  
A **forensic-grade drive wipe utility** (GUI + Rust wiping engine) that picks the safest, most effective erase method for the hardware you’re pointing at — **USB / HDD overwrite**, **ATA Secure Erase** for SATA SSD/HDD, and **NVMe Sanitize / Format NVM** for NVMe drives.

> ⚠️ **Destructive by design:** this project permanently erases data. Use on the correct device only.

---

## What it does

EternalRust is built around a small “wipe engine” that:

1. **Detects device type** (USB, HDD, SATA SSD, NVMe)
2. **Selects an erase strategy** appropriate for that device
3. **Executes the wipe**
4. Produces a **machine-readable audit record** (`WipeResult` → pretty JSON)

A GUI (built with [`iced`](https://github.com/iced-rs/iced)) wraps the engine with guardrails like preflight checks, blocking, progress, and post-wipe formatting.

---

## Features

### Safety & UX
- **Elevation handling**
  - Windows: relaunch via UAC (`Start-Process -Verb RunAs`)
  - Linux: relaunch via `sudo`
- **Preflight checks** before destructive operations
- **Device blocklist** (persisted) to prevent “oops, wrong disk”
- **Progress reporting + ETA** for overwrite-based wipes
- **Post-wipe formatting workflow** (volume label support)

### Wiping standards (pass schedules)
EternalRust supports common wipe standards via `WipeStandard`:

- **NIST SP 800-88 Rev.1**
  - `Clear`: 1-pass overwrite (0x00)
  - `Purge`: prefer hardware erase (ATA Secure Erase / NVMe Sanitize), fallback to Clear
- **DoD 5220.22-M (3-pass)**
  - 0x00 → 0xFF → Random (+ verify)
- **DoD 5220.22-M ECE (extended multi-pass)**
- **Gutmann 35-pass** (legacy magnetic-media oriented)
- **Custom** pass schedules:
  - `Fixed(u8)`, `Random`, `Complement`

### Hardware-aware strategies
The engine chooses the wipe method based on detected `DeviceType`:

| Device type | Preferred method |
|---|---|
| **USB** | Multi-pass **software overwrite** |
| **HDD** | Software overwrite; **ATA Secure Erase** if supported and not frozen |
| **SATA SSD** | **ATA Secure Erase** / **Enhanced Secure Erase** |
| **NVMe** | **NVMe Sanitize** (best available) → fallback **Format NVM** |
| **Unknown** | Safe fallback: software overwrite |

---

## Algorithms & internals

### 1) Device detection
Implemented in `src/detect.rs`.

#### Linux
- Uses **sysfs** (`/sys/block/<dev>/...`) to classify devices:
  - NVMe: `nvme*` naming convention
  - USB: sysfs link path contains `usb`
  - SSD vs HDD: `queue/rotational` (`0` = non-rotational)
- Reads metadata (size, sector size, model, serial, removable)
- Probes capabilities:
  - **ATA security** (supported / frozen / enhanced erase)
  - **NVMe sanitize caps** (`SANICAP` bits)

#### Windows
- Detection is currently a **stub** returning `Unknown` (placeholders for future `DeviceIoControl` work)

---

### 2) Software overwrite wiping (USB / HDD fallback)
Implemented in `src/wipe/usb.rs`.

**Core approach**
- Writes directly to the raw device using buffered I/O.
- Uses a **4 MiB** write buffer per operation.
- Reports progress every **64 MiB** written.
- After all passes: **verifies the final pass** by reading back and comparing bytes.

**Random pass reproducibility**
Random passes aren’t “write random then pray” — they’re *deterministic per pass*:
- Each `Random` pass generates a **32-byte seed**
- A `StdRng` stream is derived from that seed
- Verification regenerates the exact same byte stream and compares read-back data

**Pass resolution**
A pass schedule is converted into “resolved passes”:
- `Fixed(b)` → constant fill
- `Random` → seeded RNG stream
- `Complement` → bitwise invert of previous pass (fixed or RNG stream)

---

### 3) ATA Secure Erase (SATA SSD / HDD when available)
Implemented in `src/wipe/ssd.rs`.

**Procedure (Linux SG_IO passthrough)**
Commands are issued via **SCSI Generic `SG_IO`** using an **ATA-PASS-THROUGH(16)** CDB:

1. `IDENTIFY DEVICE` (0xEC)  
   Parses security status word (word 128) to confirm:
   - security supported
   - not frozen
   - enhanced erase supported (optional)
2. `SECURITY SET PASSWORD` (0xF1)  
   Sets a **temporary 32-byte password**
3. `SECURITY ERASE PREPARE` (0xF3)
4. `SECURITY ERASE UNIT` (0xF4)  
   Uses **Enhanced Secure Erase** when supported **and** the requested standard is `Nist80088Purge`

**Frozen security state**
If ATA security is **frozen**, the engine refuses and asks you to unfreeze (common workaround: suspend/resume).

---

### 4) NVMe Sanitize / Format NVM
Implemented in `src/wipe/nvme.rs`.

**Linux ioctl approach**
Uses the kernel `NVME_IOCTL_ADMIN_CMD` ioctl to send admin commands directly to the **controller** device (`/dev/nvme0`, not `/dev/nvme0n1`).

**Commands implemented**
- Identify Controller (read `SANICAP`)
- Sanitize
- Get Log Page (poll sanitize status)
- Format NVM (secure erase settings)

**Erase selection priority**
The engine auto-selects the strongest supported method:

1. **Sanitize Crypto Erase**
2. **Sanitize Block Erase**
3. **Sanitize Overwrite**
4. **Format NVM** fallback:
   - Crypto erase if supported
   - User data erase otherwise

---

## Audit output

Every wipe returns a structured `WipeResult`:
- requested standard
- actual method used (software overwrite / ATA / NVMe mode)
- bytes processed, passes completed
- verification status (for overwrite wipes)
- timestamps (start/end)
- messages/warnings
- can be serialized to **pretty JSON** via `to_json()`

This is designed for chain-of-custody style reporting and logging.

---

## Installation / Building

EternalRust is written in **Rust** and can be built from source on Windows and Linux.

> ⚠️ **Administrator/root privileges are required to wipe raw drives.**

### Prerequisites

Install the Rust toolchain:

- Rust installer: https://rustup.rs

After installation verify:
rustc --version
cargo --version

Running "cargo build" in the main directory will place an executable in the "target/debug" folder. If you run it on Windows, it gives you an exe. If ran on Linux, it gives you a Linux binary.

---
### Credits
- **Icons by [Icons8](https://icons8.com)**
---

## Project structure

```text
src/
  main.rs           # GUI app + workflow orchestration
  detect.rs         # device classification + capability probing
  types.rs          # core enums + audit/result types
  error.rs          # wipe error model
  wipe/
    mod.rs          # WipeEngine orchestrator
    usb.rs          # multi-pass overwrite + verification
    ssd.rs          # ATA Secure Erase via SG_IO (Linux)
    nvme.rs         # NVMe admin ioctls (Linux)
assets/
  icon_16.png       # window icon
