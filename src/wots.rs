/*
 * WOTS+ algorithms, based on:
 * [KKW25] Khovratovich, D., Kudinov, M. and Wagner, B., 'At the Top of the Hypercube - Better Size-Time Tradeoffs for Hash-Based Signatures', Aug 2025
 * [QSZ26] Qin, Z., Sun, S. and Zheng, F., 'Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths', Oct 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::params::{N, W, V, D0, WOTS_SIG}; // parameter values

use crate::tweakable_hashes::{prf, f, t_v}; // hash function instantiations

use crate::u256::{U256, ZERO, u256_from_be, u256_add, u256_sub, u256_lt, shr_to_u256, mul_wide, bit_len}; // WOTS+ parameter computation stuff

/////////////////////// WOTS+ PRECOMPUTATION CODE ///////////////////////

type Table = [[U256; D0 + 1]; V];

/// TABLE[k-1][e] = number of ways to split budget e over k chains, each in 0..W
/// (i.e. l_e^{<k>}). Only e <= D0 is stored; truncation is exact because
/// entry e depends only on entries <= e of the previous row.
const fn build_ell() -> Table {
    let mut t: Table = [[ZERO; D0 + 1]; V];
    let mut e = 0;
    while e < W && e <= D0 { t[0][e] = [1, 0, 0, 0]; e += 1; }        // k = 1
    let mut k = 2;
    while k <= V {
        t[k - 1][0] = t[k - 2][0];
        let mut e = 1;
        while e <= D0 {
            let mut s = u256_add(t[k - 1][e - 1], t[k - 2][e]);
            if e >= W { s = u256_sub(s, t[k - 2][e - W]); }            // sliding window
            t[k - 1][e] = s;
            e += 1;
        }
        k += 1;
    }
    t
}

const TABLE: Table = build_ell();       // evaluated once at compile time
static ELL: Table = TABLE;              // single copy in the binary: index this at runtime
const ELL_TOP: U256 = TABLE[V - 1][D0]; // l_{d0}^{<v>}: size of the layer we map into

/// Hash output bytes needed: log2(l_d0) + 64 bits of slack, so the rescaling bias is ~2^-64.
const DIGEST_LEN: usize = (bit_len(ELL_TOP) + 64 + 7) / 8;
const _: () = assert!(DIGEST_LEN <= 32, "widen U256 if this fires");

/////////////////////// HELPER FUNCTIONS ///////////////////////
 
// fn map_to_vertex(
//     _x: usize, // input message
// ) -> [usize; V] {

//     // 1. set x_i = x and d_1 = PARAMS.d0

//     // 2. for i from 1 to v-1:

//     // 2a. find j_i in {0, ..., w-1} s.t. sum_{0<=j<j_i} l_{d_i-j}^{<v-i>} <= x_i < sum_{0<=j<=j_i} l_{d_i-j}^{<v-i>}

//     // 2b. set a_i = w - j_i in [w]

//     // 2c. set d_{i+1} = d_i - j_i = d_i - (w - a_i)

//     // 2d. set x_{i+1} = x_i - sum_{0<=j<j} l_{d_i-j}^{<v-i>}

//     // 3. set a_v = w - x_v - d_v

//     // 4. output (a_1, a_2, ..., a_v)

//     let a: [usize; V] = [0; V];

//     a
    
// }

/// Unrank x in [0, l_d^{<v>}) to verifier-step counts j_i (sum == d, each < w), v = j.len().
fn unrank(mut x: U256, mut d: usize, w: usize, ell: impl Fn(usize, usize) -> U256, j: &mut [usize]) {
    let v = j.len();
    for i in 0..v - 1 {
        let k = v - 1 - i;                      // chains left after this one (paper's v-i)
        let mut ji = 0;
        loop {
            assert!(ji < w, "x out of range for this layer");
            let block = if ji <= d { ell(k, d - ji) } else { ZERO };
            if u256_lt(&x, &block) { break; }   // x falls inside this block
            x = u256_sub(x, block);             // otherwise skip it
            ji += 1;
        }
        j[i] = ji;
        d -= ji;
    }
    debug_assert!(x == ZERO && d < w);          // 1-chain tail: exactly one vertex
    j[v - 1] = d;                               // last chain takes the remaining budget
}

// MapToVertex for the production parameters. Returns j_i = w - a_i (verifier steps).
fn map_to_vertex(x: U256) -> [usize; V] {
    debug_assert!(u256_lt(&x, &ELL_TOP));
    let mut j = [0usize; V];
    unrank(x, D0, W, |k, e| ELL[k - 1][e], &mut j);
    j
}

// map a digest to signature indices, i.e. one chain index per chain,
// indicating per chain how many times the signer must iteratively hash
fn top_single_layer(
    digest: &[u8; N], // message digest
) -> [usize; V] {

    // z is the digest as a big-endian integer
    let z: U256 = u256_from_be(digest);

    // x = floor(z * l_d0 / 2^(8*N))
    let x: U256 = shr_to_u256(&mul_wide(&z, &ELL_TOP), 8 * N);

    // j indicates for each chain how many times *the verifier* has to hash the chain to get to the end value 
    let j = map_to_vertex(x);

    // transform j into the signature indices of how many times *the signer* has to hash the chains
    // a_i = w - j_i in [1, w], so the signer hashes a_i - 1 = w-1-j_i times
    let mut a = [0usize; V];
    for i in 0..V { a[i] = W - 1 - j[i]; }

    debug_assert_eq!(a.iter().sum::<usize>(), V * (W - 1) - D0);

    a
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 5 FROM SLH-DSS (FIPS 205)                          |
| Chaining function used in WOTS+.                             |
+-------------------------------------------------------------*/
fn chain(
    input: &[u8; N], // value to hash iteratively
    mut i: u32,         // position in the chain
    steps: u32,         // number of hash evaluations to do
    pk_seed: &[u8; N],  // PK.seed
    mut adrs: Adrs,     // ADRS
) -> [u8; N] // -> buffer
{

    // target = i + steps
    let t: u32 = i + steps;

    // initialise the output to the input
    let mut output: [u8; N] = [0u8; N];
    output.copy_from_slice(input);

    // iterate over the hash evaluations
    while i < t {

        // update the hash iteration in ADRS
        adrs.set_hash_addr(i);

        // compute the hash of the previous chain value, and overwrite it
        let digest: [u8; N] = f(pk_seed, &adrs, &output);
        output.copy_from_slice(&digest);

        i += 1;

    }

    output
}

/*-------------------------------------------------------------+
| ALGORITHM 6 FROM SLH-DSS (FIPS 205)                          |
| Generates a WOTS+ public key.                                |
+-------------------------------------------------------------*/
pub fn wots_pkgen(
    sk_seed: &[u8; N], // SK.seed
    pk_seed: &[u8; N], // PK.seed
    mut adrs: Adrs,    // ADRS
) -> [u8; N] // -> pk
{

    // initialise the array that will hold all concatenated chain values
    let mut chains: [[u8; N]; V] = [[0u8; N]; V];

    // clone ADRS and set the correct type for computing WOTS+ secret keys
    let mut skadrs: Adrs = Adrs::clone(&adrs);
    skadrs.set_type_and_clear(adrs_type::WOTS_PRF);
    
    // get the key pair address from ADRS, and set it in skadrs
    skadrs.set_key_pair_addr(adrs.get_key_pair_addr());

    // compute all secret key values
    for idx_chain in 0..V {
        
        // update the chain address in ADRS
        skadrs.set_chain_addr(idx_chain as u32);
        
        // compute the WOTS+ secret key value
        chains[idx_chain].copy_from_slice(&prf(&pk_seed, &sk_seed, &skadrs));

    }
    
    // compute all public key values
    for idx_chain in 0..V {
        
        // update the chain address in ADRS
        adrs.set_chain_addr(idx_chain as u32);

        let start: u32 = 0;            // start index is the first chain value (the secret key value)
        let steps: u32 = (W as u32)-1; // evaluate the entire hash chain to the last chain value (the public key value)

        // compute the WOTS+ public key value
        let sig_val: [u8; N] = chain(&chains[idx_chain], start, steps, &pk_seed, adrs);
        chains[idx_chain].copy_from_slice(&sig_val);

    }

    // set the correct type for computing the WOTS+ public key
    let mut wotspkadrs: Adrs = Adrs::clone(&adrs);
    wotspkadrs.set_type_and_clear(adrs_type::WOTS_PK);
    wotspkadrs.set_key_pair_addr(adrs.get_key_pair_addr());
    
    // compute the WOTS+ overall public key by hashing all public key chain values together
    let pk: [u8; N] = t_v(&pk_seed, &adrs, &chains);

    pk
}

/*-------------------------------------------------------------+
| ALGORITHM 7 FROM SLH-DSS (FIPS 205)                          |
| Generates a WOTS+ signature on an n-byte message.            |
+-------------------------------------------------------------*/
pub fn wots_sign(
    m: &[u8; N],       // message to sign (XMSS tree root or PORS+FP public key)
    sk_seed: &[u8; N], // SK.seed
    pk_seed: &[u8; N], // PK.seed
    mut adrs: Adrs,    // ADRS
) -> [u8; WOTS_SIG] // -> sig_wots
{

    // initialise the WOTS+ signature
    let mut sig_wots: [u8; WOTS_SIG] = [0u8; WOTS_SIG];

    // compute the chain lengths based on the message
    let lengths: [usize; V] = top_single_layer(&m);
    
    // clone ADRS and set the correct type for computing WOTS+ secret keys
    let mut skadrs: Adrs = Adrs::clone(&adrs);
    skadrs.set_type_and_clear(adrs_type::WOTS_PRF);
    
    // get the key pair address from ADRS, and set it in skadrs
    skadrs.set_key_pair_addr(adrs.get_key_pair_addr());

    // compute all secret key values
    for idx_chain in 0..V {

        // update the chain address in ADRS
        skadrs.set_chain_addr(idx_chain as u32);

        // compute the WOTS+ secret key value
        let sk_wots: [u8; N] = prf(&pk_seed, &sk_seed, &skadrs);

        // store the secret key value in the WOTS+ signature (to overwrite int he next loop)
        sig_wots[idx_chain*N..(idx_chain+1)*N].copy_from_slice(&sk_wots);

    }

    // compute all signature values
    for idx_chain in 0..V {

        // update the chain address in ADRS
        adrs.set_chain_addr(idx_chain as u32);

        let start: u32 = 0;                         // start index is the first chain value (the secret key value)
        let steps: u32 = lengths[idx_chain] as u32; // evaluate the hash chain to the signature value
        
        // take the secret key value computed in the previous loop
        let mut sk_wots: [u8; N] = [0u8; N];
        sk_wots.copy_from_slice(&sig_wots[idx_chain*N..(idx_chain+1)*N]);
        
        // compute the WOTS+ signature value
        let pk_wots: [u8; N] = chain(&sk_wots, start, steps, &pk_seed, adrs);

        // store the signature value in the WOTS+ signature
        sig_wots[idx_chain*N..(idx_chain+1)*N].copy_from_slice(&pk_wots);

    }

    sig_wots
}

/*-------------------------------------------------------------+
| ALGORITHM 8 FROM SLH-DSS (FIPS 205)                          |
| Computes a WOTS+ public key from a message and its           |
| signature.                                                   |
+-------------------------------------------------------------*/
pub fn wots_pkfromsig(
    _sig_wots: &[u8; WOTS_SIG], // WOTS+ signature
    _m: &[u8; N],               // message (XMSS root or FORS public key)
    _pk_seed: &[u8; N],         // PK.seed
    mut _adrs: Adrs,            // ADRS
) -> [u8; N] // -> pk_wots
{



    let pk_wots: [u8; N] = [0u8; N];

    pk_wots
}