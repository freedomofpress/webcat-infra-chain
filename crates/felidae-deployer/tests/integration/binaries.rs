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

/// Find the cometbft binary.
///
/// Search order:
/// 1. System PATH (e.g., from nix environment)
/// 2. Local submodule build at `./cometbft/build/cometbft`
pub fn find_cometbft() -> color_eyre::Result<PathBuf> {
    // First, check if cometbft is available on PATH (e.g., from nix environment)
    if let Ok(output) = Command::new("which").arg("cometbft").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    // Fall back to local submodule build (for non-nix systems)
    let local_build = PathBuf::from("./cometbft/build/cometbft");
    if local_build.exists() && local_build.is_file() {
        return Ok(local_build.canonicalize()?);
    }

    Err(color_eyre::eyre::eyre!(
        "cometbft binary not found. Either:\n\
         - Run in the nix environment (nix develop), or\n\
         - Build the cometbft submodule: cd cometbft && make build"
    ))
}
