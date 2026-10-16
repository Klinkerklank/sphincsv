/*
 * SPHINCS+V parameters
 * 
 * author: Dennis op 't Roodt 2026-10-16 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::u256::{U256, U256_ZERO, U256_ONE, wots_find_d0, u256_add, u256_sub, u256_bitlen}; // WOTS+ parameter computation stuff

/* input parameter constants */

pub const N: usize = 16;        // security parameter
pub const LAMBDA: usize = 128;  // security parameter
pub const LG_W: usize = 4;      // log of Winternitz parameter
pub const H: usize = 65;        // total hypertree height
pub const D: usize = 12;        // number of layers in the hypertree
pub const MMAX: usize = 178;    // maximum number of authentication path nodes in a PORS+FP signature
pub const T: usize = 33*(1<<6); // number of leaves in the PORS+FP tree
pub const K: usize = 33;        // number of revealed leaves in a PORS+FP signature

/* derived parameter constants */

// SPHINCS+V parameters
pub const SKBYTES: usize = 4*N; // SK = [SK.seed, SK.prf, PK.seed, PK.root], each limb being N bytes
pub const PKBYTES: usize = 2*N; // PK =                  [PK.seed, PK.root], each limb being N bytes
pub const MD_LEN: usize = N;    // byte length of the string to sign using PORS+FP
pub const IDX_TREE_LEN: usize = ceil_div(H_PRIME_LO, 8);     // byte length of the lowest-layer XMSS tree index
pub const IDX_LEAF_LEN: usize = ceil_div(H - H_PRIME_LO, 8); // byte length of the leaf index within an XMSS tree
pub const M: usize = MD_LEN + IDX_TREE_LEN + IDX_LEAF_LEN;        // total required byte length of H_msg output 

// WOTS+ parameters
pub const W: usize = 1 << LG_W;
const WOTS_PARAMS: (usize, usize) = wots_params();
pub const V: usize = WOTS_PARAMS.0;  // number of WOTS+ chains
pub const D0: usize = WOTS_PARAMS.1; // number of hashes the verifier computes

// XMSS and HT parameters
pub const H_PRIME_LO: usize = H/D;     // height of the shorter XMSS trees
pub const H_PRIME_HI: usize = H/D + 1; // height of the taller XMSS trees
pub const D_LO: usize = D - H%D;       // # HT layers with H_PRIME_LO-height XMSS trees
pub const D_HI: usize = H%D;           // # HT layers with H_PRIME_HI-height XMSS trees
pub const XMSS_TREE_SIZE: usize = (1 << (H_PRIME_HI + 1)) - 1; // upperbound of XMSS tree size

// PORS+FP parameters
pub const H_BAR: usize = ceil_log2(T);                    // height of the PORS (without pruning) tree
pub const PORS_TREE_SIZE: usize = (1 << (H_BAR + 1)) - 1; // number of nodes in the PORS (without pruning) tree

// signature component byte lengths
pub const WOTS_SIG: usize = V*N; // includes one N-byte signature value for each of the V chains
pub const XMSS_LO_SIG: usize = WOTS_SIG + H_PRIME_LO*N; // includes a WOTS+ signature and H_PRIME_LO N-byte authentication path nodes
pub const XMSS_HI_SIG: usize = WOTS_SIG + H_PRIME_HI*N; // includes a WOTS+ signature and H_PRIME_HI N-byte authentication path nodes
pub const HT_SIG: usize = D_LO*XMSS_LO_SIG + D_HI*XMSS_HI_SIG; // includes XMSS signatures for D_LO layers of XMSS trees of height XMSS_LO_SIG, and D_HI layers of XMSS trees of height XMSS_HI_SIG
pub const PORS_SIG: usize = 4 + K*N + MMAX*N; // counter is four bytes, K N-byte leaves are revealed, number of N-byte authentication path nodes is at most MMAX
pub const SPXV_SIG: usize = N + PORS_SIG + HT_SIG; // includes N-byte message randomiser, PORS+FP signature on the message hash, and HT signature on the PORS+FP root

/* helper functions */

const fn ceil_log2(x: usize) -> usize {
    if x <= 1 { 0 } else { usize::BITS as usize - (x-1).leading_zeros() as usize }
}

const fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

/////////////////////// WOTS+ PRECOMPUTATION CODE ///////////////////////

// hypercube layer sizes, where rows are indexed by k-1 (chains) and columns by e (budgets):
// LAYER_SIZES[k-1][e]
//   = l_e^{<k>}
//   = the number of ways to choose (j_0, ..., j_{k-1}) with each j_i in 0..W and j_0 + ... + j_{k-1} == e
// only budgets up to D0 are ever needed (map_to_vertex starts at D0 and only decreases), so the table is truncated at D0
type LayerSizes = [[U256; D0 + 1]; V];

const TABLE: LayerSizes = build_layer_sizes();   // build the table with hypercube layer sizes
pub static LAYER_SIZES: LayerSizes = TABLE;      // runtime access to the table
pub const TOP_LAYER_SIZE: U256 = TABLE[V-1][D0]; // l_{d0}^{<v>}: size of the layer to map into

// number of digest bytes needed such that mapping a digest uniformly onto [0, TOP_LAYER_SIZE-1] is almost unbiased
pub const WOTS_ENC_LEN: usize = (u256_bitlen(TOP_LAYER_SIZE) + 64 + 7) / 8;

// x is in a U256, so the digest cannot be longer than 32 bytes
// if this assertion fails, the parameter set needs a wider integer type
// (and wider mul_wide / shr_to_u256)
const _: () = assert!(WOTS_ENC_LEN <= 32, "widen U256 if this fires");

// build the table of l_e^{<k>} for k = 0..V and e = 0..D0:
//   l_e^{<1>} = 1 for 0 <= e < W, else 0
//   l_e^{<k>} = sum_{j=0}^{W-1} l_{e-j}^{<k-1>} with l_x = 0 for x < 0
// instead of computing W additions per entry, use a sliding window:
//   l_e^{<k>}     = l_{e-W+1}^{<k-1>} + ... + l_e^{<k-1>}
//   l_{e-1}^{<k>} = l_{e-W}^{<k-1>}   + ... + l_{e-1}^{<k-1>}
// truncation at D0 is exact: entry (k, e) only reads (k, e-1), (k-1, e) and (k-1, e-W),
// which all have budget <= e, so no entry <= D0 ever depends on one > D0
const fn build_layer_sizes() -> LayerSizes {

    let mut t: LayerSizes = [[U256_ZERO; D0 + 1]; V];

    // row k = 0: one chain, so exactly one way for each budget 0..W-1, none above
    let mut e: usize = 0;
    while e < W && e <= D0 {

        t[0][e] = U256_ONE; // U256 value 1
        e += 1;

    }

    // rows k = 1..V-1: each row is built from the previous one.
    let mut k: usize = 1;
    while k < V {

        // budget 0: every chain must take j = 0, so there is exactly one way
        t[k][0] = t[k-1][0];

        let mut e = 1;
        while e <= D0 {

            // l_{e-1}^{<k>} + l_e^{<k-1>}: shift the window by one, adding the new term on its right edge
            let mut s = u256_add(t[k][e-1], t[k-1][e]);

            // drop the term that just left the window on the left edge (budget e-W, valid once e >= W)
            if e >= W { s = u256_sub(s, t[k-1][e-W]); } // sliding window
            t[k][e] = s;
            e += 1;

        }

        k += 1;

    }

    t
}

/*-------------------------------------------------------------+
| CONSTRUCTION 5 FROM [KKW25]                                  |
| Find the parameters for the Top Single Layer algorithm.      |
+-------------------------------------------------------------*/
// 1. select W, V such that W^V > 2^(LAMBDA + log4 LAMBDA)
// (W and LAMBDA are input parameters, so compute V)
// 2. find the minimum D0 such that l_D0 >= 2^lambda
const fn wots_params() -> (usize, usize) {

    let mut v = 1; // start at the smallest potential V

    loop {

        // W^V > 2^(LAMBDA + log4(LAMBDA)) <=> 2*V*log2(W) > 2*LAMBDA + log2(LAMBDA)
        let feasible: bool = 2 * v * LG_W > 2 * LAMBDA + ceil_log2(LAMBDA);

        if feasible {

            // check whether a layer D0 exists with enough nodes
            // (V being feasible doesn't guarantee D0 to exist)
            if let Some(d0) = wots_find_d0(W, v, LAMBDA) {
                return (v, d0);
            }

        }

        v += 1; // increment to the next V to try

    }

}
