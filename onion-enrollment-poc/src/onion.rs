//! Off-circuit reference math: real .onion v3 parsing, real Ed25519, real SHA3-256.
//!
//! This is the *production* math — the circuit module mirrors the same shape with
//! arkworks-friendly stand-ins (SHA-256 + Jubjub) for benchmarking purposes.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use data_encoding::BASE32_NOPAD;
use sha3::{Digest, Sha3_256};

pub const ONION_VERSION: u8 = 0x03;
pub const WEBCAT_PREFIX: &[u8] = b"webcat-blind-v1:";

#[derive(Debug)]
pub struct OnionAddress {
    pub address: String,
    pub pubkey: [u8; 32],
}

pub fn parse_onion(addr: &str) -> Result<OnionAddress, String> {
    let stripped = addr.trim_end_matches(".onion").to_uppercase();
    let bytes = BASE32_NOPAD
        .decode(stripped.as_bytes())
        .map_err(|e| format!("base32 decode: {e}"))?;
    if bytes.len() != 35 {
        return Err(format!("expected 35 bytes after base32 decode, got {}", bytes.len()));
    }
    if bytes[34] != ONION_VERSION {
        return Err(format!("bad version byte 0x{:02x}", bytes[34]));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[..32]);

    // Verify checksum: SHA3-256(".onion checksum" || PUBKEY || VERSION)[..2]
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(&pk);
    h.update([ONION_VERSION]);
    let cs = h.finalize();
    if cs[0] != bytes[32] || cs[1] != bytes[33] {
        return Err("checksum mismatch — not a valid v3 onion address".into());
    }

    Ok(OnionAddress { address: addr.to_string(), pubkey: pk })
}

/// h_wc = SHA3-256("webcat-blind-v1:" || KP_hs_id) — raw 32 bytes
pub fn h_wc_bytes(pk: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(WEBCAT_PREFIX);
    h.update(pk);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// h_wc reduced mod the Ed25519 group order so it can act as a scalar.
pub fn h_wc_scalar(pk: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(h_wc_bytes(pk))
}

/// KP_wc_blind = [h_wc] · KP_hs_id, computed on the real Ed25519 curve.
pub fn compute_kp_wc_blind(pk: &[u8; 32]) -> Result<[u8; 32], String> {
    let kp: EdwardsPoint = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or("public key is not a valid Edwards point")?;
    let h = h_wc_scalar(pk);
    Ok((h * kp).compress().to_bytes())
}
