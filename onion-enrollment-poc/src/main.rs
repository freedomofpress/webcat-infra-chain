//! End-to-end driver: generate a real Ed25519 keypair, compute reference
//! values for both blinded keys (with the spec-shaped Tor input), build the
//! hardened circuit (with subgroup check + public inputs), check it satisfies,
//! then run Groth16 setup / prove / verify against the matching public-input
//! vector.

use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr as Native};
use ark_curve25519::Fq;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::fields::nonnative::params::OptimizationType;
use ark_r1cs_std::fields::nonnative::AllocatedNonNativeFieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use sha3::{Digest, Sha3_256};

use onion_enrollment_poc::circuit::{
    WebcatCircuit, TOR_BASE_POINT_DECIMAL_STR, TOR_BLIND_STRING, TOR_N_PREFIX, WEBCAT_PREFIX,
};
use onion_enrollment_poc::ed25519::plaintext;

/// Generate a "real" Ed25519 keypair (using our plaintext implementation).
/// Returns (sk_bits_le, pk_xy, pk_bytes_canonical).
fn gen_keypair(rng_seed: u64) -> (Vec<bool>, (Fq, Fq), [u8; 32]) {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
    let mut sk_bytes = [0u8; 32];
    rng.fill(&mut sk_bytes);
    let sk_bits: Vec<bool> = (0..256)
        .map(|i| (sk_bytes[i / 8] >> (i % 8)) & 1 == 1)
        .collect();
    let pk_xy = plaintext::scalar_mul(plaintext::generator(), &sk_bits);
    let pk_bytes = plaintext::encode_point(pk_xy);
    (sk_bits, pk_xy, pk_bytes)
}

/// Compute h = SHA3-256(input) as a 256-bit LE bit vector — the form the
/// circuit's WEBCAT scalar mult consumes.
fn hash_to_scalar_bits(input: &[u8]) -> Vec<bool> {
    let mut h = Sha3_256::new();
    h.update(input);
    let digest: [u8; 32] = h.finalize().into();
    (0..256)
        .map(|i| (digest[i / 8] >> (i % 8)) & 1 == 1)
        .collect()
}

/// Compute h_tor = clamp(SHA3-256(input)) as a 256-bit LE bit vector, matching
/// Tor's blinding-factor derivation (RFC 8032 §5.1.5 scalar clamping).
fn hash_to_clamped_scalar_bits(input: &[u8]) -> Vec<bool> {
    let mut bits = hash_to_scalar_bits(input);
    bits[0] = false;
    bits[1] = false;
    bits[2] = false;
    bits[254] = true;
    bits[255] = false;
    bits
}

/// Build the Tor blinding-factor hash input per `rend-spec/keyblinding-scheme`.
/// `B` is the textual decimal tuple of the Ed25519 base point's (x, y),
/// not the canonical 32-byte encoding — matching Tor's reference impl.
fn tor_blinding_input(pk_bytes: &[u8; 32], period_num: u64, period_length: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        TOR_BLIND_STRING.len()
            + 32
            + TOR_BASE_POINT_DECIMAL_STR.len()
            + TOR_N_PREFIX.len()
            + 16,
    );
    v.extend_from_slice(TOR_BLIND_STRING);
    v.extend_from_slice(pk_bytes);
    v.extend_from_slice(TOR_BASE_POINT_DECIMAL_STR);
    v.extend_from_slice(TOR_N_PREFIX);
    v.extend_from_slice(&period_num.to_be_bytes());
    v.extend_from_slice(&period_length.to_be_bytes());
    v
}

/// Convert one Curve25519 base-field element into the Vec<Native> public-input
/// representation that NonNativeFieldVar's `new_input` allocator expects.
fn fq_to_public_inputs(v: Fq) -> Vec<Native> {
    AllocatedNonNativeFieldVar::<Fq, Native>::get_limbs_representations(
        &v,
        OptimizationType::Constraints,
    )
    .expect("limb decomposition")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WEBCAT zero-knowledge proof — hardened circuit ===\n");

    // ----------------------------------------------------------------
    // 1.  Generate a real Ed25519 keypair and reference blinded keys.
    // ----------------------------------------------------------------
    let (_sk_bits, pk_xy, pk_bytes) = gen_keypair(0xC0FFEE);
    println!("[reference data]");
    println!("  pk_bytes (canonical Ed25519)  = {}", hex::encode(pk_bytes));

    // h_wc = clamp(SHA3-256("webcat-blind-v1:" ‖ pk_bytes))
    let mut wc_input = WEBCAT_PREFIX.to_vec();
    wc_input.extend_from_slice(&pk_bytes);
    let h_wc_bits = hash_to_clamped_scalar_bits(&wc_input);
    let blind_wc_xy = plaintext::scalar_mul(pk_xy, &h_wc_bits);
    println!(
        "  blind_wc.y (low 8 bytes hex)  = {}",
        hex::encode(&blind_wc_xy.1.into_bigint().to_bytes_le()[..8])
    );

    // Tor side — full rend-spec layout, with Ed25519 clamping on h_tor.
    let period_num: u64 = 60_000;
    let period_length: u64 = 1440; // minutes, per spec
    let tor_input = tor_blinding_input(&pk_bytes, period_num, period_length);
    let h_tor_bits = hash_to_clamped_scalar_bits(&tor_input);
    let blind_tor_xy = plaintext::scalar_mul(pk_xy, &h_tor_bits);
    println!(
        "  blind_tor.y (low 8 bytes hex) = {}",
        hex::encode(&blind_tor_xy.1.into_bigint().to_bytes_le()[..8])
    );
    println!("  period_num                    = {}", period_num);
    println!("  period_length                 = {}", period_length);
    println!("  tor input length              = {} bytes", tor_input.len());
    println!();

    // ----------------------------------------------------------------
    // 2.  Build the circuit and check satisfiability.
    // ----------------------------------------------------------------
    let circuit = WebcatCircuit {
        pubkey_bytes: pk_bytes,
        pubkey_xy: pk_xy,
        blind_wc_xy,
        blind_tor_xy,
        period_num,
        period_length,
    };

    println!("[circuit shape]");
    let t = Instant::now();
    let cs = ConstraintSystem::<Native>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    cs.finalize();
    println!("  synthesis time   = {:.2} s", t.elapsed().as_secs_f64());
    println!("  num constraints  = {}", cs.num_constraints());
    println!("  num witness vars = {}", cs.num_witness_variables());
    println!("  num input vars   = {}", cs.num_instance_variables());
    let satisfied = cs.is_satisfied()?;
    println!("  satisfied?       = {}", satisfied);
    if !satisfied {
        if let Some(unsatisfied) = cs.which_is_unsatisfied()? {
            eprintln!("first unsatisfied constraint: {}", unsatisfied);
        }
        std::process::exit(1);
    }
    println!();

    // ----------------------------------------------------------------
    // 3.  Build the matching public-input vector for verify().
    // ----------------------------------------------------------------
    let mut public_inputs: Vec<Native> = Vec::new();
    public_inputs.extend(fq_to_public_inputs(blind_wc_xy.0));
    public_inputs.extend(fq_to_public_inputs(blind_wc_xy.1));
    public_inputs.extend(fq_to_public_inputs(blind_tor_xy.0));
    public_inputs.extend(fq_to_public_inputs(blind_tor_xy.1));
    // Period parameters: one native field element per u64, in the same
    // allocation order as `WebcatCircuit::generate_constraints`.
    public_inputs.push(Native::from(period_num));
    public_inputs.push(Native::from(period_length));
    println!(
        "[public input vector] {} BLS12-381 scalars",
        public_inputs.len()
    );
    println!();

    // ----------------------------------------------------------------
    // 4.  Groth16 setup / prove / verify.
    // ----------------------------------------------------------------
    println!("[Groth16 / BLS12-381]");
    let mut rng = rand::thread_rng();

    let t = Instant::now();
    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)?;
    let setup_s = t.elapsed().as_secs_f64();
    println!("  setup       = {:.2} s", setup_s);

    let mut pk_buf = Vec::new();
    pk.serialize_compressed(&mut pk_buf)?;
    let mut vk_buf = Vec::new();
    vk.serialize_compressed(&mut vk_buf)?;
    println!(
        "  pk size     = {} bytes ({:.2} GB)",
        pk_buf.len(),
        pk_buf.len() as f64 / 1e9
    );
    println!("  vk size     = {} bytes", vk_buf.len());
    drop(pk_buf); // free 2-3 GB before proving

    let t = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)?;
    let prove_s = t.elapsed().as_secs_f64();
    println!("  proving     = {:.2} s", prove_s);

    let mut proof_buf = Vec::new();
    proof.serialize_compressed(&mut proof_buf)?;
    println!("  proof size  = {} bytes (compressed)", proof_buf.len());

    let t = Instant::now();
    let ok = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;
    let verify_us = t.elapsed().as_micros();
    println!("  verifying   = {} µs", verify_us);
    println!("  verified?   = {}", ok);
    assert!(ok, "Groth16 verification failed");

    println!("\n=== Done ===");
    Ok(())
}
