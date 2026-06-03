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
        return Err(format!(
            "expected 35 bytes after base32 decode, got {}",
            bytes.len()
        ));
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

    // MANDATORY torsion check. The enrollment ZK circuit deliberately omits the
    // in-circuit prime-order subgroup check on KP_hs_id (≈2.5M constraints) and
    // relies on this off-circuit gate instead: clamping makes the *blinded
    // outputs* cofactor-safe, but a torsion-tainted master key can still satisfy
    // the circuit, so it must be rejected here. Without this, the circuit's
    // size optimization would weaken the proof statement. See circuit.rs.
    decode_identity_key(&pk)?;

    Ok(OnionAddress {
        address: addr.to_string(),
        pubkey: pk,
    })
}

/// Decode a 32-byte Ed25519 onion identity key (`KP_hs_id`) to a curve point,
/// enforcing that it is a valid, canonically-encoded point **in the prime-order
/// subgroup** (torsion-free). This is the off-circuit subgroup check the ZK
/// circuit delegates to the client; it must be applied to every `KP_hs_id`
/// before it is trusted or used in any blinded-key derivation.
pub fn decode_identity_key(pk: &[u8; 32]) -> Result<EdwardsPoint, String> {
    let point = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or("public key is not a valid Edwards point")?;
    if !point.is_torsion_free() {
        return Err("public key is not in the prime-order subgroup (torsion-tainted)".into());
    }
    Ok(point)
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

/// h_wc as a scalar: the SHA3-256 digest is **clamped** per RFC 8032 §5.1.5
/// (bits 0,1,2 cleared; bit 254 set; bit 255 cleared) and then reduced mod the
/// Ed25519 group order. The clamp is required: the spec defines
/// `h_wc = clamp(H("webcat-blind-v1:" || KP_hs_id))`, and it must match the
/// in-circuit derivation (`circuit.rs`) bit-for-bit, otherwise the browser-side
/// lookup key (§3.4) would disagree with the enrolled `KP_wc_blind`.
///
/// For a prime-order `KP_hs_id` (enforced by [`decode_identity_key`]), reducing
/// `clamp(h)` mod L before the multiply yields the same point as the circuit's
/// double-and-add over the full `clamp(h)`. The reduction does *not* preserve
/// `clamp(h) ≡ 0 (mod 8)` (since `L ≡ 5 mod 8`), so torsion-freeness of the key
/// is what makes the two derivations agree — hence the mandatory subgroup check.
pub fn h_wc_scalar(pk: &[u8; 32]) -> Scalar {
    let mut h = h_wc_bytes(pk);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    Scalar::from_bytes_mod_order(h)
}

/// KP_wc_blind = [h_wc] · KP_hs_id, computed on the real Ed25519 curve.
/// Rejects keys that are not in the prime-order subgroup (see
/// [`decode_identity_key`]).
pub fn compute_kp_wc_blind(pk: &[u8; 32]) -> Result<[u8; 32], String> {
    let kp = decode_identity_key(pk)?;
    let h = h_wc_scalar(pk);
    Ok((h * kp).compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::traits::Identity;

    /// A genuine prime-order onion identity key: [k]·B.
    fn prime_order_pk() -> ([u8; 32], EdwardsPoint) {
        let kp = ED25519_BASEPOINT_POINT * Scalar::from(0xC0FFEEu64);
        (kp.compress().to_bytes(), kp)
    }

    /// Find a valid, decodable Edwards point that is NOT in the prime-order
    /// subgroup (has a torsion component). ~7/8 of decodable points qualify,
    /// so this terminates almost immediately.
    fn torsion_tainted_pk() -> [u8; 32] {
        for i in 1u64..100_000 {
            let mut pk = [0u8; 32];
            pk[..8].copy_from_slice(&i.to_le_bytes());
            if let Some(p) = CompressedEdwardsY(pk).decompress() {
                if !p.is_torsion_free() {
                    return pk;
                }
            }
        }
        panic!("no torsion-tainted point found in search range");
    }

    /// Build a syntactically valid v3 .onion address (correct checksum) for an
    /// arbitrary 32-byte pubkey — including torsion-tainted ones.
    fn make_onion(pk: &[u8; 32]) -> String {
        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(pk);
        h.update([ONION_VERSION]);
        let cs = h.finalize();
        let mut bytes = Vec::with_capacity(35);
        bytes.extend_from_slice(pk);
        bytes.push(cs[0]);
        bytes.push(cs[1]);
        bytes.push(ONION_VERSION);
        format!("{}.onion", BASE32_NOPAD.encode(&bytes))
    }

    /// Reference double-and-add over little-endian scalar bits — the exact
    /// algorithm the circuit (and main.rs) uses, on real dalek points.
    fn scalar_mul_bits_le(point: EdwardsPoint, bits_le: &[bool]) -> EdwardsPoint {
        let mut acc = EdwardsPoint::identity();
        for &bit in bits_le.iter().rev() {
            acc = acc + acc;
            if bit {
                acc = acc + point;
            }
        }
        acc
    }

    /// P2 regression: the off-circuit KP_wc_blind must equal the circuit's
    /// clamped double-and-add derivation, not the raw mod-order one.
    #[test]
    fn h_wc_derivation_matches_circuit() {
        let (pk, kp) = prime_order_pk();

        // Circuit-shaped reference: clamp(SHA3) as LE bits, double-and-add.
        let digest = h_wc_bytes(&pk);
        let mut bits: Vec<bool> = (0..256)
            .map(|i| (digest[i / 8] >> (i % 8)) & 1 == 1)
            .collect();
        bits[0] = false;
        bits[1] = false;
        bits[2] = false;
        bits[254] = true;
        bits[255] = false;
        let want = scalar_mul_bits_le(kp, &bits).compress().to_bytes();

        assert_eq!(compute_kp_wc_blind(&pk).unwrap(), want);
    }

    /// Documents the bug that was fixed: the old unclamped mod-order scalar
    /// produces a different KP_wc_blind, which would break browser lookups.
    #[test]
    fn unclamped_mod_order_derivation_differs() {
        let (pk, kp) = prime_order_pk();
        let old = (Scalar::from_bytes_mod_order(h_wc_bytes(&pk)) * kp)
            .compress()
            .to_bytes();
        assert_ne!(
            old,
            compute_kp_wc_blind(&pk).unwrap(),
            "clamped and unclamped derivations must differ for this key"
        );
    }

    #[test]
    fn parse_onion_accepts_prime_order_key() {
        let (pk, _) = prime_order_pk();
        let addr = make_onion(&pk);
        let parsed = parse_onion(&addr).expect("prime-order onion should parse");
        assert_eq!(parsed.pubkey, pk);
    }

    #[test]
    fn parse_onion_rejects_torsion_tainted_key() {
        let pk = torsion_tainted_pk();
        let addr = make_onion(&pk);
        let err = parse_onion(&addr).expect_err("torsion-tainted onion must be rejected");
        assert!(
            err.contains("prime-order subgroup"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compute_kp_wc_blind_rejects_torsion_tainted_key() {
        let pk = torsion_tainted_pk();
        assert!(compute_kp_wc_blind(&pk).is_err());
    }
}
