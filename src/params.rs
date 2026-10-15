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
const WOTS_PARAMS: (usize, usize) = wots_params();
pub const V: usize = WOTS_PARAMS.0;
pub const D0: usize = WOTS_PARAMS.1;

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
pub const SPXV_SIG: usize = N + PORS_SIG + HT_SIG;

/* helper functions */

const fn ceil_log2(x: usize) -> usize {
    if x <= 1 { 0 } else { usize::BITS as usize - (x-1).leading_zeros() as usize }
}

const fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
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
            if let Some(d0) = d0_for(LG_W, v, LAMBDA) {
                return (v, d0);
            }

        }

        v += 1; // increment to the next V to try

    }

}
