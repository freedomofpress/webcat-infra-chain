//! Binary discovery utilities for integration tests.
//!
//! This module provides functions to locate the felidae and cometbft binaries
//! required for running integration tests.

use std::path::PathBuf;
use std::process::Command;

/// Find binaries for testing.
///
/// Returns a tuple of (cometbft_path, felidae_path).
pub fn find_binaries() -> color_eyre::Result<(PathBuf, PathBuf)> {
    // Try to build/find felidae using escargot with explicit package
    let felidae_build = escargot::CargoBuild::new()
        .package("felidae")
        .bin("felidae")
        .current_release()
        .current_target()
        .run()?;
    let felidae_bin = felidae_build.path().to_path_buf();

    // Look for cometbft in common locations
    let cometbft_bin = find_cometbft()?;

    Ok((cometbft_bin, felidae_bin))
}

/// Find the cometbft binary on the system PATH.
pub fn find_cometbft() -> color_eyre::Result<PathBuf> {
    // Assume cometbft is available on PATH (provided by nix environment)
    if let Ok(output) = Command::new("which").arg("cometbft").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err(color_eyre::eyre::eyre!(
        "cometbft binary not found in PATH. Ensure you're running in the nix environment (nix develop)"
    ))
}
