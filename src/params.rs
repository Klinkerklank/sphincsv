/*
 * SPHINCS+V parameters
 * 
 * author: Dennis op 't Roodt 2026-10-13 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::u256::d0_for; // WOTS+ parameter computation stuff

/* input parameter constants */

pub const N: usize = 16;
pub const LG_W: usize = 4;
pub const LAMBDA: usize = 128;
pub const H: usize = 66;
pub const D: usize = 22;
pub const MMAX: usize = 178;
pub const T: usize = 33 * (1<<6);
pub const K: usize = 33;

/* derived parameter constants */

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

/* helper functions */

const fn ceil_log2(x: usize) -> usize {
    if x <= 1 { 0 } else { usize::BITS as usize - (x-1).leading_zeros() as usize }
}

const fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

const fn spx_v() -> usize {
    let mut v = 1;
    loop {
        // w^v > 2^(lambda + log4 lambda)  <=>  2*v*lg_w > 2*lambda + log2(lambda)
        let feasible = 2 * v * LG_W > 2 * LAMBDA + ceil_log2(LAMBDA);
        if feasible {
            if let Some(_) = d0_for(LG_W, v, LAMBDA) {
                return v;
            }
        }
        v += 1;
    }
}

const fn spx_d0() -> usize {
    // find the minimum hypercube layer d0 such that l_d0 >= 2^lambda
    match d0_for(LG_W, V, LAMBDA) {
        Some(d) => d,
        None => panic!("no layer with >= 2^lambda vertices"),
    }
}
