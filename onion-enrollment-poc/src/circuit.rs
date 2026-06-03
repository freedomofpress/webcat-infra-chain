//! Hardened WEBCAT circuit using real Ed25519 + real SHA3-256, with the
//! spec-shaped Tor blinding input, the Ed25519 clamping on `h_tor`, and
//! public-input exposure of the two blinded keys plus the Tor period
//! parameters. The prime-order subgroup check on `pk_point` is delegated to
//! the client (see note in `generate_constraints`): clamping makes the
//! blinded outputs cofactor-safe, and the browser re-checks torsion on
//! receipt, so the expensive in-circuit `[L]·pk_point` multiply is omitted.
//!
//! # Statement
//!
//! Given a private witness consisting of an Ed25519 master public key
//! `KP_hs_id` (as a curve point and as its 32-byte canonical encoding), and
//! public inputs `KP_wc_blind`, `KP_hs_blind`, `period_num`, `period_length`,
//! the circuit enforces:
//!
//! ```text
//! 1. pk_bytes is the canonical Ed25519 encoding of pk_point.
//! 2. pk_point lies on the Ed25519 curve.
//! 3. KP_wc_blind  = [clamp(SHA3-256("webcat-blind-v1:" || pk_bytes))]
//!                 * pk_point.
//! 4. KP_hs_blind  = [clamp(SHA3-256(BLIND_STRING || pk_bytes || B || N))]
//!                 * pk_point
//!    where
//!      BLIND_STRING = "Derive temporary signing key" || INT_1(0)
//!      B            = the Ed25519 base point as the textual ASCII decimal
//!                     tuple "(x_decimal, y_decimal)" — 158 bytes including
//!                     the parentheses, comma, and space. NOT the 32-byte
//!                     canonical encoding. Matches Tor's reference
//!                     implementation (little-t-tor).
//!      N            = "key-blind" || INT_8(period_num) || INT_8(period_length)
//!      clamp        = standard Ed25519 scalar clamping per RFC 8032 5.1.5
//!    (rend-spec/keyblinding-scheme; INT_n is n-byte big-endian.)
//! ```

use ark_bls12_381::Fr as Native;
use ark_curve25519::Fq;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::ed25519::{ed_two_scalar_mul_le_windowed_same_base, EdPointVar};
use crate::keccak::sha3_256;


pub const WEBCAT_PREFIX: &[u8] = b"webcat-blind-v1:";
/// Tor v3 blinding-factor BLIND_STRING (rend-spec/keyblinding-scheme):
/// `"Derive temporary signing key" || INT_1(0)` — 29 bytes.
pub const TOR_BLIND_STRING: &[u8] = b"Derive temporary signing key\x00";
/// Tor v3 N prefix — `"key-blind"`, 9 bytes.
pub const TOR_N_PREFIX: &[u8] = b"key-blind";
/// Tor v3 base point `B` for the blinding-factor hash input
/// (rend-spec/keyblinding-scheme): the *textual* decimal tuple of the
/// Ed25519 base point's (x, y) coordinates, **not** the 32-byte canonical
/// encoding. 158 bytes total.
pub const TOR_BASE_POINT_DECIMAL_STR: &[u8] =
    b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, \
      46316835694926478169428394003475163141307993866256225615783033603165251855960)";

#[derive(Clone)]
pub struct WebcatCircuit {
    /// Private: 32-byte canonical Ed25519 encoding of `KP_hs_id`.
    pub pubkey_bytes: [u8; 32],
    /// Private: `KP_hs_id` as an affine curve point (x, y).
    pub pubkey_xy: (Fq, Fq),
    /// **Public input**: `KP_wc_blind` (affine).
    pub blind_wc_xy: (Fq, Fq),
    /// **Public input**: `KP_hs_blind` (affine).
    pub blind_tor_xy: (Fq, Fq),
    /// **Public input**: Tor period number. Allocated as 8 individual UInt8
    /// public inputs (big-endian) so the verifier binds the proof to the
    /// claimed period.
    pub period_num: u64,
    /// **Public input**: Tor period length. Same layout as `period_num`.
    pub period_length: u64,
}

impl ConstraintSynthesizer<Native> for WebcatCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Native>) -> Result<(), SynthesisError> {
        // -------- Public inputs first (allocation order matters for verify) --------
        // Order:
        //   1. blind_wc.x       (NonNativeFieldVar — 17 native limbs)
        //   2. blind_wc.y       ( "                              " )
        //   3. blind_tor.x      ( "                              " )
        //   4. blind_tor.y      ( "                              " )
        //   5. period_num       (1 native field element, value = period_num as u64)
        //   6. period_length    (1 native field element, value = period_length as u64)
        let blind_wc_x =
            ark_r1cs_std::fields::nonnative::NonNativeFieldVar::<Fq, Native>::new_input(
                cs.clone(),
                || Ok(self.blind_wc_xy.0),
            )?;
        let blind_wc_y =
            ark_r1cs_std::fields::nonnative::NonNativeFieldVar::<Fq, Native>::new_input(
                cs.clone(),
                || Ok(self.blind_wc_xy.1),
            )?;
        let blind_tor_x =
            ark_r1cs_std::fields::nonnative::NonNativeFieldVar::<Fq, Native>::new_input(
                cs.clone(),
                || Ok(self.blind_tor_xy.0),
            )?;
        let blind_tor_y =
            ark_r1cs_std::fields::nonnative::NonNativeFieldVar::<Fq, Native>::new_input(
                cs.clone(),
                || Ok(self.blind_tor_xy.1),
            )?;
        // Period parameters: one native FpVar input per u64, range-checked
        // to fit in 64 bits and re-assembled into 8 big-endian UInt8s for
        // the SHA3 input.
        let period_num_var =
            FpVar::<Native>::new_input(cs.clone(), || Ok(Native::from(self.period_num)))?;
        let period_length_var =
            FpVar::<Native>::new_input(cs.clone(), || Ok(Native::from(self.period_length)))?;
        let period_num_bytes = fpvar_to_be_bytes_u64(&period_num_var)?;
        let period_length_bytes = fpvar_to_be_bytes_u64(&period_length_var)?;

        // -------- Witness pk_bytes (32 UInt8) --------
        let pk_bytes_var: Vec<UInt8<Native>> = self
            .pubkey_bytes
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        // -------- Witness pk_point and bind to pk_bytes --------
        let pk_point = EdPointVar::new_witness_xy(cs.clone(), self.pubkey_xy.0, self.pubkey_xy.1)?;
        pk_point.enforce_on_curve()?;
        pk_point.enforce_canonical_encoding(&pk_bytes_var)?;
        // NOTE: the prime-order subgroup check on `pk_point` (≈2.5M constraints,
        // a full [L]·pk_point multiply) is intentionally NOT enforced here. Both
        // scalars below are Ed25519-clamped (bits 0,1,2 cleared), so the cofactor
        // (8) is cleared and `[h]·pk_point` always lands in the prime-order
        // subgroup regardless of any torsion component in `pk_point`. The blinded
        // outputs are therefore cofactor-safe as published. The only residual
        // concern — a malicious enroller committing to a torsion-tainted master
        // key — is cheaply re-checked client-side: per the spec, the browser
        // extension performs the torsion check when it receives an onion. Moving
        // that check off-circuit is the dominant size optimization.

        // -------- h_wc = clamp(SHA3-256("webcat-blind-v1:" ‖ pk_bytes)) --------
        let mut wc_input: Vec<UInt8<Native>> =
            WEBCAT_PREFIX.iter().map(|b| UInt8::constant(*b)).collect();
        wc_input.extend_from_slice(&pk_bytes_var);
        let h_wc_bytes = sha3_256(&wc_input)?;
        let mut h_wc_bits: Vec<Boolean<Native>> = bytes_to_bits_le(&h_wc_bytes)?;
        // Ed25519 scalar clamping per RFC 8032 §5.1.5, applied the same way
        // as for h_tor below. Not required by any external protocol — Tor
        // does not specify h_wc — but applied defensively so that any
        // plaintext computation of KP_wc_blind = [h_wc] * KP_hs_id is
        // cofactor-safe even without an explicit subgroup check on the
        // input point. Bits 0,1,2 cleared; bit 254 set; bit 255 cleared.
        h_wc_bits[0] = Boolean::constant(false);
        h_wc_bits[1] = Boolean::constant(false);
        h_wc_bits[2] = Boolean::constant(false);
        h_wc_bits[254] = Boolean::constant(true);
        h_wc_bits[255] = Boolean::constant(false);

        // -------- h_tor = clamp(SHA3-256(BLIND_STRING ‖ A ‖ B ‖ N)) per rend-spec --------
        let mut tor_input: Vec<UInt8<Native>> = TOR_BLIND_STRING
            .iter()
            .map(|b| UInt8::constant(*b))
            .collect();
        // A = pk_bytes (witness).
        tor_input.extend_from_slice(&pk_bytes_var);
        // B = the Ed25519 base point as the *textual* decimal tuple
        //   "(x_decimal, y_decimal)"
        // per rend-spec/keyblinding-scheme. Not the 32-byte canonical
        // encoding — matching Tor's reference implementation.
        for b in TOR_BASE_POINT_DECIMAL_STR.iter() {
            tor_input.push(UInt8::constant(*b));
        }
        // N = "key-blind" || INT_8(period_num) || INT_8(period_length).
        // "key-blind" is constant; the two INT_8 fields are public inputs.
        for b in TOR_N_PREFIX.iter() {
            tor_input.push(UInt8::constant(*b));
        }
        tor_input.extend_from_slice(&period_num_bytes);
        tor_input.extend_from_slice(&period_length_bytes);
        let h_tor_bytes = sha3_256(&tor_input)?;
        let mut h_tor_bits: Vec<Boolean<Native>> = bytes_to_bits_le(&h_tor_bytes)?;

        // Ed25519 scalar clamping per RFC 8032 §5.1.5, applied to the
        // SHA3-256 output to form `h_tor` exactly as Tor does:
        //   h[0]  &= 248    → clears bits 0,1,2 of byte 0
        //   h[31] &= 63     → clears bits 6,7 of byte 31
        //   h[31] |= 64     → sets   bit  6   of byte 31
        // Equivalent LE-bit overrides: bits 0,1,2 = 0; bit 254 = 1; bit 255 = 0.
        // This must match Tor's derivation so that `KP_hs_blind` computed
        // in-circuit equals the `KP_hs_blind` Tor publishes to HSDirs.
        h_tor_bits[0] = Boolean::constant(false);
        h_tor_bits[1] = Boolean::constant(false);
        h_tor_bits[2] = Boolean::constant(false);
        h_tor_bits[254] = Boolean::constant(true);
        h_tor_bits[255] = Boolean::constant(false);

        // -------- Two scalar mults (windowed, variable base, shared table) --------
        let (pk_wc, pk_tor) =
            ed_two_scalar_mul_le_windowed_same_base(&pk_point, &h_wc_bits, &h_tor_bits)?;

        // -------- Enforce equality with the public blinded keys --------
        // pk_wc has projective (X, Y, Z); blind_wc is affine (Z = 1 implicit):
        //     pk_wc.x * 1 == blind_wc.x * pk_wc.z
        //     pk_wc.y * 1 == blind_wc.y * pk_wc.z
        let want_wc_x = &blind_wc_x * &pk_wc.z;
        let want_wc_y = &blind_wc_y * &pk_wc.z;
        pk_wc.x.enforce_equal(&want_wc_x)?;
        pk_wc.y.enforce_equal(&want_wc_y)?;

        let want_tor_x = &blind_tor_x * &pk_tor.z;
        let want_tor_y = &blind_tor_y * &pk_tor.z;
        pk_tor.x.enforce_equal(&want_tor_x)?;
        pk_tor.y.enforce_equal(&want_tor_y)?;

        Ok(())
    }
}

fn bytes_to_bits_le(bytes: &[UInt8<Native>]) -> Result<Vec<Boolean<Native>>, SynthesisError> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for b in bytes {
        out.extend(b.to_bits_le()?);
    }
    Ok(out)
}

/// Decompose an FpVar known to hold a `u64` value into 8 big-endian UInt8s.
/// Enforces the high (above-64-bit) bits of the field element are zero, then
/// re-assembles the low 64 bits into byte groups and reverses for BE order.
fn fpvar_to_be_bytes_u64(v: &FpVar<Native>) -> Result<Vec<UInt8<Native>>, SynthesisError> {
    let bits = v.to_bits_le()?;
    let zero = Boolean::constant(false);
    // Enforce upper bits are zero so the FpVar fits in u64.
    for b in &bits[64..] {
        b.enforce_equal(&zero)?;
    }
    // bits[0..64] are LE bits of the u64; chunked into 8 bytes (LE byte order).
    let le_bytes: Vec<UInt8<Native>> = bits[0..64].chunks(8).map(UInt8::from_bits_le).collect();
    // Reverse for big-endian byte order.
    let be_bytes: Vec<UInt8<Native>> = le_bytes.into_iter().rev().collect();
    Ok(be_bytes)
}

#[cfg(test)]
mod measure {
    //! Synthesis-only constraint counter — no Groth16 setup/prove. Used to size
    //! optimizations quickly. Witness values are dummy: the constraint *count*
    //! is independent of assignments.
    use super::*;
    use ark_curve25519::Fq;
    use ark_ff::{One, Zero};
    use ark_relations::r1cs::ConstraintSystem;

    fn dummy_circuit() -> WebcatCircuit {
        WebcatCircuit {
            pubkey_bytes: [0u8; 32],
            pubkey_xy: (Fq::zero(), Fq::one()),
            blind_wc_xy: (Fq::zero(), Fq::one()),
            blind_tor_xy: (Fq::zero(), Fq::one()),
            period_num: 60_000,
            period_length: 1440,
        }
    }

    #[test]
    fn measure_constraints() {
        let cs = ConstraintSystem::<Native>::new_ref();
        dummy_circuit().generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let n = cs.num_constraints();
        let domain = (n + cs.num_instance_variables()).next_power_of_two();
        eprintln!(
            "MEASURED num_constraints = {n}  | FFT domain = {domain} (2^{})",
            domain.trailing_zeros()
        );
    }

    #[test]
    #[ignore] // slow (~Groth16 setup); run explicitly with `--ignored`
    fn measure_setup_pk_size() {
        use ark_bls12_381::Bls12_381;
        use ark_groth16::Groth16;
        use ark_serialize::CanonicalSerialize;
        use ark_snark::SNARK;
        let mut rng = rand::thread_rng();
        let t = std::time::Instant::now();
        let (pk, _vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit(), &mut rng).unwrap();
        let setup_s = t.elapsed().as_secs_f64();
        let mut buf = Vec::new();
        pk.serialize_compressed(&mut buf).unwrap();
        eprintln!(
            "MEASURED setup = {:.1}s | pk size = {} bytes ({:.2} GB)",
            setup_s,
            buf.len(),
            buf.len() as f64 / 1e9
        );
    }
}
