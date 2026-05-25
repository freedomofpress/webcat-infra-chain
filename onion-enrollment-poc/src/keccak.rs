//! SHA3-256 R1CS gadget for arkworks.
//!
//! Implements the Keccak-f[1600] permutation and the SHA3-256 sponge construction
//! over `Boolean<F>` bits, following FIPS 202.
//!
//! Tested against the `sha3` crate as a reference oracle.

use ark_ff::PrimeField;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::SynthesisError;

/// Rho rotation offsets, indexed [x][y]. FIPS 202 §3.2.2 Table 2.
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Iota round constants. FIPS 202 §3.2.5.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082,
    0x8000_0000_0000_808a, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808b, 0x0000_0000_8000_0001,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008a, 0x0000_0000_0000_0088,
    0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
    0x0000_0000_8000_808b, 0x8000_0000_0000_008b,
    0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
    0x0000_0000_0000_800a, 0x8000_0000_8000_000a,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080,
    0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

/// SHA3-256 rate in bytes (1088 bits).
const RATE_BYTES: usize = 136;

/// One Keccak lane: 64 bits, index 0 = LSB.
type Lane<F> = Vec<Boolean<F>>;
/// Keccak state: 5×5 lanes, indexed [x][y].
type State<F> = Vec<Vec<Lane<F>>>;

fn empty_state<F: PrimeField>() -> State<F> {
    (0..5)
        .map(|_| {
            (0..5)
                .map(|_| (0..64).map(|_| Boolean::constant(false)).collect())
                .collect()
        })
        .collect()
}

fn xor_lanes<F: PrimeField>(a: &Lane<F>, b: &Lane<F>) -> Result<Lane<F>, SynthesisError> {
    a.iter().zip(b.iter()).map(|(x, y)| x.xor(y)).collect()
}

/// Left-rotate a lane by `n` bits (cyclic, modulo 64). Free in R1CS — pure relabeling.
fn rotl<F: PrimeField>(lane: &Lane<F>, n: u32) -> Lane<F> {
    let n = (n % 64) as usize;
    if n == 0 {
        return lane.clone();
    }
    // Left rotate: new[i] = old[(i - n) mod 64]  ==  old[(i + 64 - n) % 64]
    (0..64).map(|i| lane[(i + 64 - n) % 64].clone()).collect()
}

/// theta: A'[x,y] = A[x,y] XOR D[x],
/// where D[x] = parity(col x-1) XOR rotl(parity(col x+1), 1).
fn theta<F: PrimeField>(s: &State<F>) -> Result<State<F>, SynthesisError> {
    // C[x] = XOR over y of A[x,y]
    let mut c: Vec<Lane<F>> = Vec::with_capacity(5);
    for x in 0..5 {
        let mut acc = s[x][0].clone();
        for y in 1..5 {
            acc = xor_lanes(&acc, &s[x][y])?;
        }
        c.push(acc);
    }
    // D[x] = C[x-1] XOR rotl(C[x+1], 1)
    let mut d: Vec<Lane<F>> = Vec::with_capacity(5);
    for x in 0..5 {
        let cm = &c[(x + 4) % 5];
        let cp = rotl(&c[(x + 1) % 5], 1);
        d.push(xor_lanes(cm, &cp)?);
    }
    let mut out = empty_state();
    for x in 0..5 {
        for y in 0..5 {
            out[x][y] = xor_lanes(&s[x][y], &d[x])?;
        }
    }
    Ok(out)
}

/// rho: rotate each lane by per-(x,y) offset. Free.
fn rho<F: PrimeField>(s: &State<F>) -> State<F> {
    let mut out = empty_state();
    for x in 0..5 {
        for y in 0..5 {
            out[x][y] = rotl(&s[x][y], RHO[x][y]);
        }
    }
    out
}

/// pi: lane permutation A'[y, (2x+3y) mod 5] = A[x, y]. Free.
fn pi<F: PrimeField>(s: &State<F>) -> State<F> {
    let mut out = empty_state();
    for x in 0..5 {
        for y in 0..5 {
            let nx = y;
            let ny = (2 * x + 3 * y) % 5;
            out[nx][ny] = s[x][y].clone();
        }
    }
    out
}

/// chi: A'[x,y,z] = A[x,y,z] XOR ((NOT A[x+1,y,z]) AND A[x+2,y,z]). Nonlinear step.
fn chi<F: PrimeField>(s: &State<F>) -> Result<State<F>, SynthesisError> {
    let mut out = empty_state();
    for x in 0..5 {
        for y in 0..5 {
            let xp1 = &s[(x + 1) % 5][y];
            let xp2 = &s[(x + 2) % 5][y];
            let mut new_lane: Lane<F> = Vec::with_capacity(64);
            for z in 0..64 {
                let not_xp1 = xp1[z].not();
                let and_term = not_xp1.and(&xp2[z])?;
                new_lane.push(s[x][y][z].xor(&and_term)?);
            }
            out[x][y] = new_lane;
        }
    }
    Ok(out)
}

/// iota: XOR lane (0,0) with the round constant. XOR with constant is free
/// (it either keeps the bit or flips it via Boolean::not).
fn iota<F: PrimeField>(s: &mut State<F>, round: usize) {
    let rc = RC[round];
    let mut new_lane: Lane<F> = Vec::with_capacity(64);
    for z in 0..64 {
        let bit = ((rc >> z) & 1) == 1;
        if bit {
            new_lane.push(s[0][0][z].not());
        } else {
            new_lane.push(s[0][0][z].clone());
        }
    }
    s[0][0] = new_lane;
}

/// The Keccak-f[1600] permutation: 24 rounds.
pub fn keccak_f<F: PrimeField>(mut s: State<F>) -> Result<State<F>, SynthesisError> {
    for round in 0..24 {
        s = theta(&s)?;
        s = rho(&s);
        s = pi(&s);
        s = chi(&s)?;
        iota(&mut s, round);
    }
    Ok(s)
}

/// Absorb one rate-sized block of bytes into the state. The block is XOR-ed,
/// lane by lane (lane order = stream order, little-endian within each lane).
fn absorb<F: PrimeField>(state: &mut State<F>, block: &[UInt8<F>]) -> Result<(), SynthesisError> {
    debug_assert_eq!(block.len(), RATE_BYTES);
    // The first 17 lanes (in stream order (0,0)(1,0)..(4,0)(0,1)..(1,3)) cover 136 bytes.
    for lane_idx in 0..17 {
        let x = lane_idx % 5;
        let y = lane_idx / 5;
        let off = lane_idx * 8;
        let mut block_lane: Lane<F> = Vec::with_capacity(64);
        for byte_i in 0..8 {
            block_lane.extend(block[off + byte_i].to_bits_le()?);
        }
        let mut new_lane: Lane<F> = Vec::with_capacity(64);
        for z in 0..64 {
            new_lane.push(state[x][y][z].xor(&block_lane[z])?);
        }
        state[x][y] = new_lane;
    }
    Ok(())
}

/// Squeeze `n_bytes` bytes from the state, lane-by-lane, little-endian within lane.
fn squeeze<F: PrimeField>(state: &State<F>, n_bytes: usize) -> Vec<UInt8<F>> {
    let mut out = Vec::with_capacity(n_bytes);
    for byte_idx in 0..n_bytes {
        let bit_idx = byte_idx * 8;
        let lane_idx = bit_idx / 64;
        let z_off = bit_idx % 64;
        let x = lane_idx % 5;
        let y = lane_idx / 5;
        let bits: Vec<Boolean<F>> = (0..8).map(|i| state[x][y][z_off + i].clone()).collect();
        out.push(UInt8::from_bits_le(&bits));
    }
    out
}

/// SHA3-256 over a byte string. Returns 32 bytes.
///
/// Padding (FIPS 202): append `0x06` immediately after the input, zero-fill to
/// the next rate boundary, and XOR `0x80` into the last byte of the padded block.
pub fn sha3_256<F: PrimeField>(input: &[UInt8<F>]) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let mut padded: Vec<UInt8<F>> = input.to_vec();
    padded.push(UInt8::constant(0x06));
    while padded.len() % RATE_BYTES != 0 {
        padded.push(UInt8::constant(0x00));
    }
    let last = padded.len() - 1;
    padded[last] = padded[last].xor(&UInt8::constant(0x80))?;

    let mut state = empty_state::<F>();
    let n_blocks = padded.len() / RATE_BYTES;
    for blk in 0..n_blocks {
        let block = &padded[blk * RATE_BYTES..(blk + 1) * RATE_BYTES];
        absorb(&mut state, block)?;
        state = keccak_f(state)?;
    }

    Ok(squeeze(&state, 32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use sha3::{Digest, Sha3_256};

    fn run(input: &[u8]) -> ([u8; 32], usize) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let in_var: Vec<UInt8<Fr>> = input
            .iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();
        let digest = sha3_256(&in_var).unwrap();
        let bytes: Vec<u8> = digest.iter().map(|b| b.value().unwrap()).collect();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        (out, cs.num_constraints())
    }

    fn expected(input: &[u8]) -> [u8; 32] {
        Sha3_256::digest(input).into()
    }

    #[test]
    fn empty() {
        let (got, n) = run(b"");
        assert_eq!(got, expected(b""));
        eprintln!("constraints (empty): {}", n);
    }

    #[test]
    fn abc() {
        let (got, n) = run(b"abc");
        assert_eq!(got, expected(b"abc"));
        eprintln!("constraints (abc): {}", n);
    }

    #[test]
    fn webcat_prefix_plus_pubkey() {
        // "webcat-blind-v1:" || 32 zero bytes (48 bytes total — single SHA3-256 block).
        let mut input = b"webcat-blind-v1:".to_vec();
        input.extend_from_slice(&[0u8; 32]);
        let (got, n) = run(&input);
        assert_eq!(got, expected(&input));
        eprintln!("constraints (48B WEBCAT input): {}", n);
    }

    #[test]
    fn long_two_blocks() {
        // 200 bytes spans two absorb blocks.
        let input: Vec<u8> = (0u8..200).collect();
        let (got, n) = run(&input);
        assert_eq!(got, expected(&input));
        eprintln!("constraints (200B, two blocks): {}", n);
    }

    #[test]
    fn boundary_lengths() {
        // Exercise lengths that hit the padding boundaries — easy to get wrong.
        // 135 = rate-1 (suffix and 0x80 land in the same byte).
        // 136 = rate (forces a second all-padding block).
        // 137 = rate+1 (one byte spills into block 2).
        for len in [1usize, 17, 55, 64, 100, 135, 136, 137, 271, 272, 273] {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let (got, _n) = run(&input);
            assert_eq!(got, expected(&input), "mismatch at len={}", len);
        }
    }

    #[test]
    fn nist_sha3_256_test_vector() {
        // FIPS 202 /  NIST CAVS sample for SHA3-256 of the empty string.
        let want = hex::decode(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        .unwrap();
        let (got, _) = run(b"");
        assert_eq!(got.to_vec(), want);
    }

}
