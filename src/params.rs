/*
 * SPHINCS+V parameters
 * 
 * author: Dennis op 't Roodt 2026-10-13 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::u256::d0_for; // WOTS+ parameter computation stuff

const PARAMS: SphincsvParams = SphincsvParams {

    // security parameter
    n: 16,

    // WOTS+
    lg_w: 4,
    lambda: 128,

    // HT and XMSS
    h: 66,
    d: 22,

    // PORS+FP
    // spx_mmax should be 156 according to the paper,
    // but the size of A is about 180-190 and so it never gets low enough
    mmax: 178,
    t:    33 * (1 << 6), // 33*(2^6)
    k:    33,

};

struct SphincsvParams {

    // security parameter
    pub n: usize,

    // WOTS+
    pub lg_w: usize,   // WOTS+ chain length
    pub lambda: usize, // security parameter

    // HT and XMSS
    pub h: usize, // total hypertree height
    pub d: usize, // number of layers of XMSS trees in the hypertree

    // PORS+FP
    pub mmax: usize, // maximum number of PORS+FP secret key values in a signature
    pub t: usize,    // total number of PORS+FP tree secret-key leaves
    pub k: usize,    // number of PORS+FP secret-key leaves revealed for a signature

}

// input parameter constants
pub const N: usize = PARAMS.n;
pub const LG_W: usize = PARAMS.lg_w;
pub const LAMBDA: usize = PARAMS.lambda;
pub const H: usize = PARAMS.h;
pub const D: usize = PARAMS.d;
pub const MMAX: usize = PARAMS.mmax;
pub const T: usize = PARAMS.t;
pub const K: usize = PARAMS.k;

// computed parameter constants:

// SPHINCS+V parameters
pub const SKBYTES: usize = 4*N;
pub const PKBYTES: usize = 2*N;
pub const MD_LEN: usize = N;
pub const IDX_LEAF_LEN: usize = ceil_div(H - H_PRIME, 8);
pub const IDX_TREE_LEN: usize = ceil_div(H_PRIME, 8);
pub const M: usize = MD_LEN + IDX_LEAF_LEN + IDX_TREE_LEN;

// WOTS+ parameters
pub const W: usize = 1 << LG_W;
pub const V: usize = spx_v();
pub const D0: usize = spx_d0();

// XMSS and HT parameters
pub const H_PRIME: usize = H / D;
pub const XMSS_TREE_SIZE: usize = (1 << (H_PRIME + 1)) - 1;

// PORS+FP parameters
pub const H_BAR: usize = ceil_log2(T);
pub const PORS_TREE_SIZE: usize = (1 << (H_BAR + 1)) - 1;

// signature component byte lengths
pub const WOTS_SIG: usize = V*N;
pub const XMSS_SIG: usize = WOTS_SIG + H_PRIME*N;
pub const HT_SIG: usize = D*XMSS_SIG;
pub const PORS_SIG: usize = 4 + K*N + MMAX*N;
pub const SPXV_SIG: usize = N + PORS_SIG + PORS_SIG;

// helper functions

const fn floor_log2(x: usize) -> usize {
    usize::BITS as usize - 1 - x.leading_zeros() as usize
}

const fn ceil_log2(x: usize) -> usize {
    if x <= 1 { 0 } else { usize::BITS as usize - (x-1).leading_zeros() as usize }
}

const fn ceil_log4(x: usize) -> usize {
    // ceil(log4 x) = ceil(ceil(log2 x) / 2)
    (ceil_log2(x) + 1) / 2
}

const fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

const fn spx_v() -> usize {
    let mut v = 1;
    // loop {
    //     // w^v > 2^(lambda + log4 lambda)  <=>  2*v*lg_w > 2*lambda + log2(lambda)
    //     let feasible = 2 * v * self.spx_lg_w > 2 * self.spx_lambda + ceil_log2(self.spx_lambda);
    //     if feasible {
    //         if let Some(_) = d0_for(self.spx_lg_w, v, self.spx_lambda) {
    //             return v;
    //         }
    //     }
    //     v += 1;
    //     if v == 128 {
    //         println!("v=128 reached and counting...");
    //     }
    // }
    v
}

const fn spx_d0() -> usize {
    // // find the minimum hypercube layer d0 such that l_d0 >= 2^lambda
    // match d0_for(self.spx_lg_w, self.spx_v(), self.spx_lambda) {
    //     Some(d) => d,
    //     None => panic!("no layer with >= 2^lambda vertices"),
    // }
    1
}
