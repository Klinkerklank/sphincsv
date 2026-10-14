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

// ELL[k-1][e] = l_e^{<k>}: the number of ways to choose (j_1, ..., j_k) with each j_i in 0..W
// (0 <= j_i <= W-1) and j_1 + ... + j_k == e. In other words, the number of vertices in
// "layer e" of a k-chain WOTS+ grid, where layer e means the verifier does e hash steps in total.
//
// Rows are indexed by k-1 (k = 1..=V chains), columns by e (budget, 0..=D0).
// Only budgets up to D0 are ever needed (map_to_vertex starts at D0 and only decreases),
// so the table is truncated at D0.
type Table = [[U256; D0 + 1]; V];

/// Builds the table of l_e^{<k>} for k = 1..=V and e = 0..=D0.
///
/// Definition (what we want):
///     l_e^{<1>} = 1                                   for 0 <= e < W, else 0
///     l_e^{<k>} = sum_{j=0}^{W-1} l_{e-j}^{<k-1>}     (the first chain takes j, the rest share e-j)
///                 with l_x = 0 for x < 0
///
/// Computing that sum directly costs W additions per entry. Instead we use a sliding window:
///     l_e^{<k>}   = l_{e-W+1}^{<k-1>} + ... + l_e^{<k-1>}          (window of W terms)
///     l_{e-1}^{<k>} = l_{e-W}^{<k-1>} + ... + l_{e-1}^{<k-1>}      (same window, shifted by one)
/// Subtracting gives:
///     l_e^{<k>} = l_{e-1}^{<k>} + l_e^{<k-1>} - l_{e-W}^{<k-1>}
/// which is one add and one subtract per entry. For e < W the subtracted term has a
/// negative index and is 0, so it is skipped.
///
/// Truncation at D0 is exact: entry (k, e) only reads (k, e-1), (k-1, e) and (k-1, e-W),
/// which all have budget <= e, so no entry <= D0 ever depends on one > D0.
///
/// `const fn` with `while` loops (no `for`, no iterators) so it can run at compile time.
const fn build_ell() -> Table {
    let mut t: Table = [[ZERO; D0 + 1]; V];

    // Row k = 1 (index 0): one chain, so exactly one way for each budget 0..W-1, none above.
    let mut e = 0;
    while e < W && e <= D0 { t[0][e] = [1, 0, 0, 0]; e += 1; }        // U256 value 1

    // Rows k = 2..=V: each row is built from the previous one.
    let mut k = 2;
    while k <= V {
        // Budget 0: every chain must take j = 0, so there is exactly one way (same as the previous row).
        // This is also the base case of the sliding-window recurrence (no e-1 term exists).
        t[k - 1][0] = t[k - 2][0];

        let mut e = 1;
        while e <= D0 {
            // l_{e-1}^{<k>} + l_e^{<k-1>}: shift the window by one, adding the new term on its right edge
            let mut s = u256_add(t[k - 1][e - 1], t[k - 2][e]);
            // Drop the term that just left the window on the left edge (budget e-W, valid once e >= W).
            if e >= W { s = u256_sub(s, t[k - 2][e - W]); }            // sliding window
            t[k - 1][e] = s;
            e += 1;
        }
        k += 1;
    }
    t
}

/// The table, evaluated once at compile time.
/// Declared `const` only so it can be used in other const expressions (ELL_TOP below).
/// A `const` is inlined at each use site, so indexing it at runtime could copy the whole table.
const TABLE: Table = build_ell();       // evaluated once at compile time

/// The table as seen by runtime code. A `static` has a single address and a single copy in the binary,
/// so `ELL[k-1][e]` in map_to_vertex is a plain memory read.
static ELL: Table = TABLE;              // single copy in the binary: index this at runtime

/// l_{d0}^{<v>}: the total number of vertices in the top layer, i.e. the size of the set
/// that map_to_vertex ranks into. Valid x values are 0 <= x < ELL_TOP.
const ELL_TOP: U256 = TABLE[V - 1][D0]; // l_{d0}^{<v>}: size of the layer we map into

/// Number of digest bytes needed so that mapping a digest uniformly onto [0, ELL_TOP) is almost unbiased.
///
/// The digest z is uniform on [0, 2^(8*len)). We compute x = floor(z * ELL_TOP / 2^(8*len)),
/// which is not exactly uniform on [0, ELL_TOP): some x get one more preimage than others.
/// The relative bias is about ELL_TOP / 2^(8*len). Taking 8*len >= log2(ELL_TOP) + 64 bits
/// makes that at most about 2^-64. The "+ 7) / 8" rounds the bit count up to whole bytes.
const DIGEST_LEN: usize = (bit_len(ELL_TOP) + 64 + 7) / 8;

/// z is held in a U256, so the digest cannot be longer than 32 bytes. If this fires,
/// the parameter set needs a wider integer type (and wider mul_wide / shr_to_u256).
const _: () = assert!(DIGEST_LEN <= 32, "widen U256 if this fires");

/////////////////////// HELPER FUNCTIONS ///////////////////////

/// MapToVertex (paper's algorithm), for the production parameters.
///
/// Input:  x in [0, l_{d0}^{<v>}), an index into the top layer
///         (the set of all vertices (a_1..a_v), each a_i in [1, w], with sum (w - a_i) = d0).
/// Output: (a_1, ..., a_v), each a_i in [1, w], with sum (w - a_i) == D0.
///
/// Notation: ELL[k-1][e] = l_e^{<k>} = number of ways to split a budget e over k chains,
/// each taking j in 0..w.
///
/// Idea: the vertices are ordered chain by chain. For chain i, the choice j_i = 0, 1, 2, ...
/// owns a contiguous block of indices of size l_{d_i - j_i}^{<v-i>}, i.e. the number of ways
/// to spread the remaining budget d_i - j_i over the remaining v-i chains.
/// We find which block x_i falls into; that gives j_i, and the offset within the block
/// becomes x_{i+1}.
fn map_to_vertex(x: U256) -> [usize; V] {
    debug_assert!(u256_lt(&x, &ELL_TOP));

    let mut a = [0usize; V]; // a[i-1] holds the paper's a_i (code is 0-indexed, paper is 1-indexed)

    // Step 1: x_1 = x, d_1 = d0.
    // x_i and d_i are updated in place: at the top of iteration i they hold x_i and d_i.
    let mut x_i: U256 = x;
    let mut d_i: usize = D0;

    // Step 2: for i from 1 to v-1
    for i in 1..V {
        // Number of chains remaining after chain i (the paper's v-i).
        let k = V - i;

        // Step 2a: find j_i in {0..w-1} such that
        //     sum_{0<=j<j_i}  l_{d_i-j}^{<v-i>}  <=  x_i  <  sum_{0<=j<=j_i} l_{d_i-j}^{<v-i>}
        // We walk j upward. `block` = l_{d_i-j}^{<v-i>} is the size of the block for choice j.
        // If x_i is not inside it, we skip the block by subtracting its size.
        // So when the loop exits, x_i has already had sum_{0<=j<j_i} l_{d_i-j}^{<v-i>}
        // subtracted. That subtraction is step 2d, merged into this loop.
        let mut j_i: usize = 0;
        loop {
            assert!(j_i < W, "x out of range for this layer");
            // l_e = 0 for e < 0: choosing j > d_i would overspend the budget.
            let block: U256 = if j_i <= d_i { ELL[k - 1][d_i - j_i] } else { ZERO };
            if u256_lt(&x_i, &block) {
                break;                      // x_i < prefix sum up to and including j: found j_i
            }
            x_i = u256_sub(x_i, block);     // x_i >= prefix sum: skip this block (part of step 2d)
            j_i += 1;
        }
        // Now: x_i == x_{i+1} = x_i(old) - sum_{0<=j<j_i} l_{d_i-j}^{<v-i>}   (step 2d done)

        // Step 2b: a_i = w - j_i, in [1, w]
        a[i - 1] = W - j_i;

        // Step 2c: d_{i+1} = d_i - j_i = d_i - (w - a_i)
        d_i -= j_i;
    }

    // After the loop, x_i and d_i hold x_v and d_v.
    // The last chain has only one choice, since l_e^{<1>} = 1 for 0 <= e < w.
    // So x_v must be 0, and the remaining budget d_v must fit in one chain (d_v < w).
    assert!(x_i == ZERO);
    assert!(d_i < W);

    // Step 3: a_v = w - x_v - d_v. Since x_v == 0 this is w - d_v.
    a[V - 1] = W - d_i;

    // Step 4: output (a_1, ..., a_v)
    a
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

    // a_i in [1, w]: the paper's vertex. The verifier hashes j_i = w - a_i times
    // to reach the chain end, so sum (w - a_i) == d0.
    let a_vertex = map_to_vertex(x);

    // Signer hashes a_i - 1 = w - 1 - j_i times (a_i - 1 in [0, w-1], the usual chain index).
    let mut a = [0usize; V];
    for i in 0..V { a[i] = a_vertex[i] - 1; }

    assert_eq!(a.iter().sum::<usize>(), V * (W - 1) - D0);

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
    sig_wots: &[u8; WOTS_SIG], // WOTS+ signature
    m: &[u8; N],               // message (XMSS root or FORS public key)
    pk_seed: &[u8; N],         // PK.seed
    mut adrs: Adrs,            // ADRS
) -> [u8; N] // -> pk_wots
{

    // compute the chain lengths based on the message
    let lengths: [usize; V] = top_single_layer(&m);

    // copy the WOTS+ signature into chains (as sig_wots is not writable)
    let mut chains: [[u8; N]; V] = [[0u8; N]; V];
    for i in 0..V {
        chains[i].copy_from_slice(&sig_wots[i*N..(i+1)*N]);
    }

    // compute all public key values
    for idx_chain in 0..V {

        // update the chain address in ADRS
        adrs.set_chain_addr(idx_chain as u32);

        let start: u32 = lengths[idx_chain] as u32; // start index is that of the signature value
        // to hash the chain to completion, we need to get to index SPX_W-1, and we are already at index 'start'
        let steps: u32 = (W as u32)-1 - start;

        // take the signature value from the WOTS+ signature
        let mut sigval: [u8; N] = [0u8; N];
        sigval.copy_from_slice(&chains[idx_chain]);

        // compute the WOTS+ public key value from the signature value
        let pk_wots: [u8; N] = chain(&sigval, start, steps, &pk_seed, adrs);

        // store the computed public key value in chains
        chains[idx_chain].copy_from_slice(&pk_wots);

    }

    // clone ADRS and set the correct type for WOTS+ public key generation
    let mut wotspkadrs: Adrs = Adrs::clone(&adrs);
    wotspkadrs.set_type_and_clear(adrs_type::WOTS_PK);

    // get the key pair address from ADRS, and set it in wotspkADRS
    wotspkadrs.set_key_pair_addr(adrs.get_key_pair_addr());
    
    // compute the WOTS+ overall public key by hashing all public key chain values together
    let pk_wots: [u8; N] = t_v(&pk_seed, &adrs, &chains);

    pk_wots
}