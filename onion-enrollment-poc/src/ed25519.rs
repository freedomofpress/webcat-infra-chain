//! Ed25519 group law as an arkworks R1CS gadget over non-native field arithmetic.
//!
//! The simulated field is F_p with p = 2^255 − 19 (Curve25519's base field),
//! emulated inside BLS12-381's scalar field via [`NonNativeFieldVar`].
//!
//! Curve constants are the **Ed25519 standard** ones (RFC 8032):
//!   * a = −1
//!   * d = −121665 / 121666 (mod p)
//!
//! Important: arkworks' `ark-curve25519` ships its own twisted Edwards curve
//! over the same base field but with different constants (a=486664, d=486660).
//! That curve is birationally equivalent to Ed25519 (same security, same R1CS
//! cost) but is *not* the curve Tor uses. We define the Ed25519 constants here
//! explicitly so the gadget can be tested against an Ed25519-correct plaintext
//! reference and would interoperate with real Ed25519 keys.
//!
//! Coordinates: extended (X, Y, Z, T), with x = X/Z, y = Y/Z, T = XY/Z.
//! Addition: the strongly-unified formula for a = −1 (8 multiplications, complete).

use ark_bls12_381::Fr as Native;
use ark_curve25519::Fq;
use ark_ff::{Field, MontFp, One, PrimeField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Curve25519 base-field element emulated inside BLS12-381's scalar field.
pub type FqVar = NonNativeFieldVar<Fq, Native>;

/// Ed25519 d = −121665 / 121666 (mod p). RFC 8032.
const ED25519_D: Fq =
    MontFp!("37095705934669439343138083508754565189542113879843219016388785533085940283555");
/// 2·d (mod p), folded for the strongly-unified addition formula.
const ED25519_TWO_D: Fq =
    MontFp!("16295367250680780974490674513165176452449235426866156013048779062215315747161");

/// The Ed25519 base point B, in canonical 32-byte encoding (RFC 8032 §5.1.5).
/// y = 4/5 mod p, x is the positive root, lsb(x) = 0, so the high "sign" bit
/// of byte 31 is 0; the encoding is `[0x58, 0x66, 0x66, …, 0x66]`.
pub const ED25519_BASE_POINT_ENCODED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// A point on Ed25519, represented in extended twisted-Edwards coordinates.
#[derive(Clone)]
pub struct EdPointVar {
    pub x: FqVar,
    pub y: FqVar,
    pub z: FqVar,
    pub t: FqVar,
}

impl EdPointVar {
    /// The identity element (0, 1) in extended coords.
    pub fn identity() -> Self {
        Self {
            x: FqVar::zero(),
            y: FqVar::one(),
            z: FqVar::one(),
            t: FqVar::zero(),
        }
    }

    /// Allocate (x, y) as a witness in affine form (Z = 1, T = X·Y), enforcing
    /// the T-consistency constraint t = x · y so the prover can't lie about t.
    pub fn new_witness_xy(
        cs: ConstraintSystemRef<Native>,
        x: Fq,
        y: Fq,
    ) -> Result<Self, SynthesisError> {
        let x_var = FqVar::new_witness(cs.clone(), || Ok(x))?;
        let y_var = FqVar::new_witness(cs.clone(), || Ok(y))?;
        let t_var = FqVar::new_witness(cs.clone(), || Ok(x * y))?;
        let xy = &x_var * &y_var;
        xy.enforce_equal(&t_var)?;
        Ok(Self {
            x: x_var,
            y: y_var,
            z: FqVar::one(),
            t: t_var,
        })
    }

    /// Enforce that the witnessed (x, y) lies on Ed25519. Only valid for Z = 1.
    /// Curve equation (a = −1): y² − x² = 1 + d · t²    where t = x·y.
    pub fn enforce_on_curve(&self) -> Result<(), SynthesisError> {
        let xx = &self.x * &self.x;
        let yy = &self.y * &self.y;
        let tt = &self.t * &self.t;
        let lhs = yy - xx;
        let d_const = FqVar::constant(ED25519_D);
        let rhs = FqVar::one() + d_const * tt;
        lhs.enforce_equal(&rhs)
    }

    /// Enforce that the witnessed point's canonical Ed25519 byte encoding equals
    /// the given 32-byte witness. Only meaningful for points with Z = 1 (e.g.
    /// freshly allocated via [`Self::new_witness_xy`]).
    ///
    /// Encoding (RFC 8032 §5.1.2): 32 bytes little-endian. Bytes 0..31 hold
    /// the 255-bit Y coordinate; bit 7 of byte 31 (i.e. global bit 255) holds
    /// `lsb(X)`, the sign of X.
    pub fn enforce_canonical_encoding(
        &self,
        bytes: &[UInt8<Native>],
    ) -> Result<(), SynthesisError> {
        assert_eq!(bytes.len(), 32, "Ed25519 encoding is exactly 32 bytes");

        // 256 bits of pk_bytes (LE within and across bytes).
        let mut pk_bits: Vec<Boolean<Native>> = Vec::with_capacity(256);
        for b in bytes {
            pk_bits.extend(b.to_bits_le()?);
        }

        // Y as bits, padded to 256 (the top bits are forced to zero by NonNative
        // reduction since Y < p < 2^255).
        let mut y_bits = self.y.to_bits_le()?;
        y_bits.resize(256, Boolean::constant(false));

        // X as bits — we only care about the LSB.
        let x_bits = self.x.to_bits_le()?;

        // pk_bits[0..255] match Y bits 0..255.
        for i in 0..255 {
            pk_bits[i].enforce_equal(&y_bits[i])?;
        }
        // pk_bits[255] (the high "sign" bit) matches lsb(X).
        pk_bits[255].enforce_equal(&x_bits[0])?;
        Ok(())
    }

    /// Allocate (x, y) as **public input** in affine form. Mirrors
    /// [`Self::new_witness_xy`] but exposes the affine coordinates as the
    /// circuit's public inputs (each FqVar input becomes several BLS12-381
    /// scalar-field elements via the non-native limb decomposition). T is kept
    /// as a witness with `t = x · y` enforced.
    pub fn new_input_xy(
        cs: ConstraintSystemRef<Native>,
        x: Fq,
        y: Fq,
    ) -> Result<Self, SynthesisError> {
        let x_var = FqVar::new_input(cs.clone(), || Ok(x))?;
        let y_var = FqVar::new_input(cs.clone(), || Ok(y))?;
        let t_var = FqVar::new_witness(cs.clone(), || Ok(x * y))?;
        let xy = &x_var * &y_var;
        xy.enforce_equal(&t_var)?;
        Ok(Self {
            x: x_var,
            y: y_var,
            z: FqVar::one(),
            t: t_var,
        })
    }

    /// Enforce that the point lies in the prime-order subgroup of order L.
    /// Computes [L]·self and checks the result is the identity (X = 0, Y = Z
    /// in projective coords). Uses ~2.5M constraints — one big constant-scalar
    /// mult, optimized via `ed_scalar_mul_le`'s constant-bit short-circuit.
    pub fn enforce_in_prime_subgroup(&self) -> Result<(), SynthesisError> {
        use ark_ff::BigInteger;
        // L = scalar field order of Curve25519 = order of the prime subgroup.
        let l_bits_le: Vec<bool> = ark_curve25519::Fr::MODULUS.to_bits_le();
        let l_bits_var: Vec<Boolean<Native>> = l_bits_le
            .iter()
            .map(|&b| Boolean::constant(b))
            .collect();
        let result = ed_scalar_mul_le(self, &l_bits_var)?;
        // Identity in extended coords: X = 0, Y/Z = 1 ⇒ Y = Z.
        result.x.enforce_equal(&FqVar::zero())?;
        result.y.enforce_equal(&result.z)?;
        Ok(())
    }

    /// Recover the affine (x, y) value (only available when the witness is concrete).
    pub fn value_affine(&self) -> Result<(Fq, Fq), SynthesisError> {
        let x = self.x.value()?;
        let y = self.y.value()?;
        let z = self.z.value()?;
        let z_inv = z.inverse().ok_or(SynthesisError::AssignmentMissing)?;
        Ok((x * z_inv, y * z_inv))
    }
}

/// Strongly-unified twisted-Edwards addition for a = −1. Complete: handles
/// identity, doubling, and `P + (−P)` correctly. 8 non-native multiplications.
pub fn ed_add(p1: &EdPointVar, p2: &EdPointVar) -> Result<EdPointVar, SynthesisError> {
    let two_d = FqVar::constant(ED25519_TWO_D);
    let two = FqVar::constant(Fq::from(2u64));

    // A = (Y1 − X1)(Y2 − X2)
    let a = (&p1.y - &p1.x) * (&p2.y - &p2.x);
    // B = (Y1 + X1)(Y2 + X2)
    let b = (&p1.y + &p1.x) * (&p2.y + &p2.x);
    // C = 2d · T1 · T2
    let c = &two_d * (&p1.t * &p2.t);
    // D = 2 · Z1 · Z2
    let d = &two * (&p1.z * &p2.z);
    let e = &b - &a;
    let f = &d - &c;
    let g = &d + &c;
    let h = &b + &a;
    Ok(EdPointVar {
        x: &e * &f,
        y: &g * &h,
        t: &e * &h,
        z: &f * &g,
    })
}

/// Doubling via the unified addition formula (suboptimal but compact).
pub fn ed_double(p: &EdPointVar) -> Result<EdPointVar, SynthesisError> {
    ed_add(p, p)
}

/// Variable-base scalar multiplication: returns [scalar] · p, where `scalar`
/// is given as little-endian bits. Standard double-and-add from MSB.
///
/// Short-circuits on `Boolean::Constant`: a constant-0 bit skips the addition
/// entirely, a constant-1 bit performs an unconditional add with no select.
/// This makes scalar mults by *constants* (e.g. multiplication by L for the
/// subgroup check) avoid the conditional-select overhead and the unconditional
/// add gate that would otherwise be wasted on zero bits.
pub fn ed_scalar_mul_le(
    p: &EdPointVar,
    scalar_bits_le: &[Boolean<Native>],
) -> Result<EdPointVar, SynthesisError> {
    let mut acc = EdPointVar::identity();
    for bit in scalar_bits_le.iter().rev() {
        acc = ed_double(&acc)?;
        match bit {
            Boolean::Constant(false) => {
                // bit = 0: no add.
            }
            Boolean::Constant(true) => {
                // bit = 1: unconditional add, no cond_select.
                acc = ed_add(&acc, p)?;
            }
            _ => {
                // Variable bit: compute both branches and conditionally select.
                let added = ed_add(&acc, p)?;
                acc = EdPointVar {
                    x: FqVar::conditionally_select(bit, &added.x, &acc.x)?,
                    y: FqVar::conditionally_select(bit, &added.y, &acc.y)?,
                    z: FqVar::conditionally_select(bit, &added.z, &acc.z)?,
                    t: FqVar::conditionally_select(bit, &added.t, &acc.t)?,
                };
            }
        }
    }
    Ok(acc)
}

/// Plaintext Ed25519 affine math — used both by `main.rs` to drive the circuit
/// with realistic data, and by tests as a reference oracle.
pub mod plaintext {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};

    /// Ed25519 generator B (RFC 8032): y = 4/5, x = the positive root.
    pub fn generator() -> (Fq, Fq) {
        let y = Fq::from(4u64) * Fq::from(5u64).inverse().unwrap();
        let x: Fq = MontFp!(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202"
        );
        (x, y)
    }

    /// Affine Edwards addition for a = −1.
    /// x3 = (x1·y2 + y1·x2) / (1 + d·x1·y1·x2·y2)
    /// y3 = (y1·y2 + x1·x2) / (1 − d·x1·y1·x2·y2)
    pub fn add(p1: (Fq, Fq), p2: (Fq, Fq)) -> (Fq, Fq) {
        let (x1, y1) = p1;
        let (x2, y2) = p2;
        let dxy = ED25519_D * x1 * y1 * x2 * y2;
        let inv_plus = (Fq::one() + dxy).inverse().unwrap();
        let inv_minus = (Fq::one() - dxy).inverse().unwrap();
        let x3 = (x1 * y2 + y1 * x2) * inv_plus;
        let y3 = (y1 * y2 + x1 * x2) * inv_minus;
        (x3, y3)
    }

    pub fn double(p: (Fq, Fq)) -> (Fq, Fq) {
        add(p, p)
    }

    pub fn scalar_mul(p: (Fq, Fq), bits_le: &[bool]) -> (Fq, Fq) {
        let mut acc = (Fq::zero(), Fq::one());
        for &bit in bits_le.iter().rev() {
            acc = double(acc);
            if bit {
                acc = add(acc, p);
            }
        }
        acc
    }

    /// Encode an Ed25519 point as 32 bytes (RFC 8032 §5.1.2).
    pub fn encode_point(p: (Fq, Fq)) -> [u8; 32] {
        let (x, y) = p;
        let y_bigint = y.into_bigint();
        let mut bytes: [u8; 32] = y_bigint.to_bytes_le().try_into().unwrap();
        let x_lsb = x.into_bigint().to_bytes_le()[0] & 1;
        bytes[31] |= x_lsb << 7;
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::RngCore;

    fn rand_bits(n: usize) -> Vec<bool> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; (n + 7) / 8];
        rng.fill_bytes(&mut bytes);
        (0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect()
    }

    fn rand_point() -> (Fq, Fq) {
        // 64-bit random scalar, enough to scatter across the group for tests.
        plaintext::scalar_mul(plaintext::generator(), &rand_bits(64))
    }

    #[test]
    fn generator_on_curve() {
        let (x, y) = plaintext::generator();
        let lhs = y * y - x * x;
        let rhs = Fq::one() + ED25519_D * (x * y) * (x * y);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn two_d_is_correct() {
        assert_eq!(ED25519_D + ED25519_D, ED25519_TWO_D);
    }

    #[test]
    fn add_matches_plaintext() {
        let p1 = rand_point();
        let p2 = rand_point();
        let expected = plaintext::add(p1, p2);

        let cs = ConstraintSystem::<Native>::new_ref();
        let v1 = EdPointVar::new_witness_xy(cs.clone(), p1.0, p1.1).unwrap();
        let v2 = EdPointVar::new_witness_xy(cs.clone(), p2.0, p2.1).unwrap();
        let v3 = ed_add(&v1, &v2).unwrap();
        assert_eq!(v3.value_affine().unwrap(), expected);
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("constraints (alloc 2 pts + ed_add): {}", cs.num_constraints());
    }

    #[test]
    fn double_matches_plaintext() {
        let p = rand_point();
        let expected = plaintext::double(p);

        let cs = ConstraintSystem::<Native>::new_ref();
        let v = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        let v2 = ed_double(&v).unwrap();
        assert_eq!(v2.value_affine().unwrap(), expected);
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("constraints (alloc 1 pt + ed_double): {}", cs.num_constraints());
    }

    #[test]
    fn scalar_mul_8bit() {
        let p = rand_point();
        let bits = rand_bits(8);
        let expected = plaintext::scalar_mul(p, &bits);

        let cs = ConstraintSystem::<Native>::new_ref();
        let p_var = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        let bits_var: Vec<Boolean<Native>> = bits
            .iter()
            .map(|&b| Boolean::new_witness(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let r = ed_scalar_mul_le(&p_var, &bits_var).unwrap();
        assert_eq!(r.value_affine().unwrap(), expected);
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("constraints (8-bit scalar mul): {}", cs.num_constraints());
    }

    use plaintext::encode_point;
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn encoding_round_trip() {
        let p = rand_point();
        let enc = encode_point(p);
        let x_lsb = (p.0.into_bigint().to_bytes_le()[0] & 1) as u8;
        assert_eq!((enc[31] >> 7) & 1, x_lsb);
        let mut y_bytes = enc;
        y_bytes[31] &= 0x7f;
        let y_recovered = Fq::from_le_bytes_mod_order(&y_bytes);
        assert_eq!(y_recovered, p.1);
    }

    #[test]
    fn enforce_encoding_accepts_valid() {
        let p = rand_point();
        let enc = encode_point(p);

        let cs = ConstraintSystem::<Native>::new_ref();
        let pk_var = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        let bytes_var: Vec<UInt8<Native>> = enc
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();
        pk_var.enforce_canonical_encoding(&bytes_var).unwrap();
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("constraints (enforce_canonical_encoding): {}", cs.num_constraints());
    }

    #[test]
    fn enforce_encoding_rejects_wrong_bytes() {
        let p = rand_point();
        let mut enc = encode_point(p);
        // Flip a bit in the y portion.
        enc[5] ^= 0x01;

        let cs = ConstraintSystem::<Native>::new_ref();
        let pk_var = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        let bytes_var: Vec<UInt8<Native>> = enc
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();
        pk_var.enforce_canonical_encoding(&bytes_var).unwrap();
        cs.finalize();
        assert!(!cs.is_satisfied().unwrap(), "should reject mismatched encoding");
    }

    #[test]
    fn enforce_encoding_rejects_wrong_sign_bit() {
        let p = rand_point();
        let mut enc = encode_point(p);
        // Flip the sign bit (bit 255).
        enc[31] ^= 0x80;

        let cs = ConstraintSystem::<Native>::new_ref();
        let pk_var = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        let bytes_var: Vec<UInt8<Native>> = enc
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();
        pk_var.enforce_canonical_encoding(&bytes_var).unwrap();
        cs.finalize();
        assert!(!cs.is_satisfied().unwrap(), "should reject wrong sign bit");
    }

    #[test]
    fn base_point_encoding_matches_plaintext() {
        let computed = encode_point(plaintext::generator());
        assert_eq!(computed, ED25519_BASE_POINT_ENCODED);
    }

    #[test]
    fn enforce_subgroup_accepts_valid_point() {
        // Any point [k]·G with k random is in the prime-order subgroup by
        // construction (G is a prime-order generator).
        let p = rand_point();

        let cs = ConstraintSystem::<Native>::new_ref();
        let pk_var = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        pk_var.enforce_in_prime_subgroup().unwrap();
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("constraints (subgroup check): {}", cs.num_constraints());
    }

    #[test]
    fn scalar_mul_256bit() {
        let p = rand_point();
        let bits = rand_bits(256);
        let expected = plaintext::scalar_mul(p, &bits);

        let cs = ConstraintSystem::<Native>::new_ref();
        let p_var = EdPointVar::new_witness_xy(cs.clone(), p.0, p.1).unwrap();
        let bits_var: Vec<Boolean<Native>> = bits
            .iter()
            .map(|&b| Boolean::new_witness(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let r = ed_scalar_mul_le(&p_var, &bits_var).unwrap();
        assert_eq!(r.value_affine().unwrap(), expected);
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("constraints (256-bit scalar mul): {}", cs.num_constraints());
    }
}
