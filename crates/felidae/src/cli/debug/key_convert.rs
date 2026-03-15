//! Convert Ed25519 public keys between CometBFT (base64) and felidae (hex) formats.

use base64::{Engine, engine::general_purpose::STANDARD};
use color_eyre::eyre::{bail, eyre};
use std::io::{self, Read};

use super::super::Run;

/// The expected length of a raw Ed25519 public key in bytes.
const ED25519_PUBKEY_LEN: usize = 32;

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum KeyFormat {
    /// CometBFT format: base64-encoded 32-byte Ed25519 public key.
    Cometbft,
    /// Felidae config format: lowercase hex-encoded 32-byte Ed25519 public key.
    Felidae,
}

/// Convert an Ed25519 public key between CometBFT (base64) and felidae (hex) formats.
///
/// Reads a single key from stdin (or as a positional argument) and writes
/// the converted key to stdout.
#[derive(clap::Args)]
pub struct ConvertKey {
    /// Input format.
    #[arg(long)]
    pub from: KeyFormat,

    /// Output format.
    #[arg(long)]
    pub to: KeyFormat,

    /// The key to convert. If omitted, reads from stdin.
    pub key: Option<String>,
}

impl Run for ConvertKey {
    async fn run(self) -> color_eyre::Result<()> {
        let input = match self.key {
            Some(k) => k,
            None => {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf
            }
        };
        let input = input.trim();

        let raw_bytes = decode_input(input, &self.from)?;

        if raw_bytes.len() != ED25519_PUBKEY_LEN {
            bail!(
                "expected {ED25519_PUBKEY_LEN}-byte Ed25519 public key, got {} bytes",
                raw_bytes.len()
            );
        }

        let output = encode_output(&raw_bytes, &self.to);
        println!("{output}");

        Ok(())
    }
}

fn decode_input(input: &str, format: &KeyFormat) -> color_eyre::Result<Vec<u8>> {
    match format {
        KeyFormat::Cometbft => STANDARD
            .decode(input)
            .map_err(|e| eyre!("invalid base64: {e}")),
        KeyFormat::Felidae => hex::decode(input).map_err(|e| eyre!("invalid hex: {e}")),
    }
}

fn encode_output(bytes: &[u8], format: &KeyFormat) -> String {
    match format {
        KeyFormat::Cometbft => STANDARD.encode(bytes),
        KeyFormat::Felidae => hex::encode(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_KEY: &str = "980ea10fd3512bcce7ffa3ed67322595ab6c4d8e1f0a2b3c4d5e6f708192a3b4";
    const BASE64_KEY: &str = "mA6hD9NRK8zn/6PtZzIllatsTY4fCis8TV5vcIGSo7Q=";
    // Raw bytes corresponding to both representations above.
    const RAW_BYTES: [u8; 32] = [
        0x98, 0x0e, 0xa1, 0x0f, 0xd3, 0x51, 0x2b, 0xcc, 0xe7, 0xff, 0xa3, 0xed, 0x67, 0x32, 0x25,
        0x95, 0xab, 0x6c, 0x4d, 0x8e, 0x1f, 0x0a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92,
        0xa3, 0xb4,
    ];

    #[test]
    fn decode_base64() {
        let bytes = decode_input(BASE64_KEY, &KeyFormat::Cometbft).unwrap();
        assert_eq!(bytes, RAW_BYTES);
    }

    #[test]
    fn decode_hex() {
        let bytes = decode_input(HEX_KEY, &KeyFormat::Felidae).unwrap();
        assert_eq!(bytes, RAW_BYTES);
    }

    #[test]
    fn encode_base64() {
        let out = encode_output(&RAW_BYTES, &KeyFormat::Cometbft);
        assert_eq!(out, BASE64_KEY);
    }

    #[test]
    fn encode_hex() {
        let out = encode_output(&RAW_BYTES, &KeyFormat::Felidae);
        assert_eq!(out, HEX_KEY);
    }

    #[test]
    fn round_trip_base64_to_hex() {
        let bytes = decode_input(BASE64_KEY, &KeyFormat::Cometbft).unwrap();
        let hex_out = encode_output(&bytes, &KeyFormat::Felidae);
        assert_eq!(hex_out, HEX_KEY);
    }

    #[test]
    fn round_trip_hex_to_base64() {
        let bytes = decode_input(HEX_KEY, &KeyFormat::Felidae).unwrap();
        let b64_out = encode_output(&bytes, &KeyFormat::Cometbft);
        assert_eq!(b64_out, BASE64_KEY);
    }

    #[test]
    fn decode_invalid_base64() {
        let result = decode_input("not-valid-base64!!!", &KeyFormat::Cometbft);
        assert!(result.is_err());
    }

    #[test]
    fn decode_invalid_hex() {
        let result = decode_input("zzzz", &KeyFormat::Felidae);
        assert!(result.is_err());
    }
}
