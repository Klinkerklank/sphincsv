/*
 * WOTS+ algorithms, based on:
 * [KKW25] Khovratovich, D., Kudinov, M. and Wagner, B., 'At the Top of the Hypercube - Better Size-Time Tradeoffs for Hash-Based Signatures', Aug 2025
 * [QSZ26] Qin, Z., Sun, S. and Zheng, F., 'Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths', Oct 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-15 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::params::{N, W, V, D0, WOTS_SIG}; // parameter values

use crate::tweakable_hashes::{prf, f, t_v}; // hash function instantiations

use crate::u256::{U256, ZERO, u256_from_be, u256_add, u256_sub, u256_lt, shr_to_u256, mul_wide, bit_len}; // WOTS+ parameter computation stuff

/////////////////////// WOTS+ PRECOMPUTATION CODE ///////////////////////

// hypercube layer sizes, where rows are indexed by k-1 (chains) and columns by e (budgets):
// LAYER_SIZES[k-1][e]
//   = l_e^{<k>}
//   = the number of ways to choose (j_0, ..., j_{k-1}) with each j_i in 0..W and j_0 + ... + j_{k-1} == e
// only budgets up to D0 are ever needed (map_to_vertex starts at D0 and only decreases), so the table is truncated at D0
type LayerSizes = [[U256; D0 + 1]; V];

const TABLE: LayerSizes = build_layer_sizes(); // build the table with hypercube layer sizes
static LAYER_SIZES: LayerSizes = TABLE;        // runtime access to the table
const TOP_LAYER_SIZE: U256 = TABLE[V-1][D0];   // l_{d0}^{<v>}: size of the layer to map into

// number of digest bytes needed such that mapping a digest uniformly onto [0, TOP_LAYER_SIZE-1] is almost unbiased
// the digest is uniform on [0, 2^(8*len)). We compute x = floor(digest * TOP_LAYER_SIZE / 2^(8*len)),
// which is not exactly uniform on [0, TOP_LAYER_SIZE): some x get one more preimage than others.
// The relative bias is about TOP_LAYER_SIZE / 2^(8*len). Taking 8*len >= log2(TOP_LAYER_SIZE) + 64 bits
// makes that at most about 2^-64. The "+ 7) / 8" rounds the bit count up to whole bytes.
const DIGEST_LEN: usize = (bit_len(TOP_LAYER_SIZE) + 64 + 7) / 8;

// x is in a U256, so the digest cannot be longer than 32 bytes
// if this assertion fails, the parameter set needs a wider integer type
// (and wider mul_wide / shr_to_u256)
const _: () = assert!(DIGEST_LEN <= 32, "widen U256 if this fires");

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
const fn build_layer_sizes() -> LayerSizes {
    let mut t: LayerSizes = [[ZERO; D0 + 1]; V];

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

/////////////////////// HELPER FUNCTIONS ///////////////////////

/*-------------------------------------------------------------+
| CONSTRUCTION 6 FROM [KKW25]                                  |
| Maps a big integer x to a vertex in layer D0 of the          |
| hypercube [W]^V.                                             |
+-------------------------------------------------------------*/
fn map_to_vertex(
    x: U256 // an index in the top hypercube layer, i.e. x in 0..l_D0^{<v>}
) -> [usize; V] { // -> (a_0, ..., a_{V-1}), each a_i in [0, W-1], with sum_{0<=i<V}(W-a_i) == D0

    assert!(u256_lt(&x, &TOP_LAYER_SIZE));

    let mut a: [usize; V] = [0usize; V]; // declare output vertex

    // 1. set x_1 = x and d_1 = D0
    // x_i and d_i are updated in place: at the top of iteration i they hold x_i and d_i
    let mut x_i: U256  = x;
    let mut d_i: usize = D0;

    // 2. for i from 1 to v-1
    for i in 1..V {

        // 2a. find j_i in {0, ..., W-1} such that
        //     sum_{0<=j<j_i} l_{d_i-j}^{<v-i>} <= x_i < sum_{0<=j<=j_i} l_{d_i-j}^{<v-i>}
        let mut j_i: usize = 0;
        loop {

            assert!(j_i < W, "x out of range for this layer");

            // block = l_{d_i-j}^{<v-i>} is the size of the block for choice j
            // l_e = 0 for e < 0: choosing j > d_i would overspend the budget
            let block: U256 = if j_i <= d_i { LAYER_SIZES[V - i - 1][d_i - j_i] } else { ZERO };

            // check whether x_i < sum_{0<=j<=j_i} l_{d_i-j}^{<v-i>}
            if u256_lt(&x_i, &block) {
                break; // found j_i
            }

            // 2d. merged into the loop:
            // subtract l_{d_i-j}^{<v-i>} from x_i, such that at the end of the loop
            // we already have x_{i+1} = x_i - sum_{0<=j<j_i} l_{d_i-j}^{<v-i>}
            x_i = u256_sub(x_i, block);

            j_i += 1; // move on to the next j_i candidate

        }

        // 2b. set a_i = W - j_i, where a_i in [W]
        // ([KKW25] uses indexing that starts at 1)
        a[i - 1] = (W - 1) - j_i;

        // 2c. set d_{i+1} = d_i - j_i = d_i - (W - a_i)
        d_i -= j_i;

    }

    // after the loop, x_i is x_V, and d_i is d_V
    // the last chain has only one choice, since l_e^{<1>} = 1 for 0 <= e < W
    // so x_V must be 0, and the remaining budget d_V must fit in one chain (d_V < W)
    assert!(x_i == ZERO);
    assert!(d_i < W);

    // 3. set a_V = W - x_V - d_V
    // (x_V == 0, so a_V = W - d_V)
    // ([KKW25] uses indexing that starts at 1)
    a[V - 1] = (W - 1) - d_i;

    // 4. output (a_1, ..., a_v)
    a
}

/*-------------------------------------------------------------+
| 'IMPLEMENTATION FOR TSL' FROM [KKW25]                        |
| PSI: Computes a checksum-free antichain encoding.            |
+-------------------------------------------------------------*/
// TODO is the digest length long enough? Does it need to be hashed again to form a long enough big integer input?
fn top_single_layer_psi(
    m: &[u8; N], // message
) -> [usize; V] {

    // 1. take as input x in {0, 1, ..., w^v-1}
    let x: U256 = u256_from_be(m);

    // 2. set x_d0 = floor(x * l_D0 / W^V)
    let x_d0: U256 = shr_to_u256(&mul_wide(&x, &TOP_LAYER_SIZE), 8 * N);

    // 3. output a = map_to_vertex(x_d0)
    let a: [usize; V] = map_to_vertex(x_d0);

    // the verifier always computes exactly D0 hashes,
    // so assert that the sum of the signature indices == V*(W-1) - D0
    assert_eq!(a.iter().sum::<usize>(), V*(W-1) - D0);

    a
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 5 FROM SLH-DSS (FIPS 205)                          |
| Chaining function used in WOTS+.                             |
+-------------------------------------------------------------*/
fn chain(
    input: &[u8; N],   // value to hash iteratively
    mut i: u32,        // position in the chain
    steps: u32,        // number of hash evaluations to do
    pk_seed: &[u8; N], // PK.seed
    mut adrs: Adrs,    // ADRS
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

    // compute the checksum-free antichain lengths based on the message
    let lengths: [usize; V] = top_single_layer_psi(&m);
    
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

        // store the secret key value in the WOTS+ signature (to overwrite in the next loop)
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

    // compute the checksum-free antichain lengths based on the message
    let lengths: [usize; V] = top_single_layer_psi(&m);

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