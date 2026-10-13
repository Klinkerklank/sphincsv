/*
 * SPHINCS+V parameters
 * 
 * author: Dennis op 't Roodt 2026-10-05 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::u256::d0_for; // WOTS+ parameter computation stuff

pub const PARAMS: SphincsvParams = SphincsvParams {

    // security parameter
    spx_n: 16,

    // WOTS+
    spx_lg_w: 4,
    spx_lambda: 128,

    // HT and XMSS
    spx_h: 66,
    spx_d: 22,

    // PORS+FP
    // spx_mmax should be 156 according to the paper,
    // but the size of A is about 180-190 and so it never gets low enough
    spx_mmax: 178,
    spx_t:    33 * (1 << 6), // 33*(2^6)
    spx_k:    33,

    // // PORS+FP
    // spx_mmax: 156,
    // spx_t:    33 * (1 << 6), // 33*(2^6)
    // spx_k:    33,

};

pub struct SphincsvParams {

    // security parameter
    pub spx_n: usize,

    // WOTS+
    pub spx_lg_w: usize,   // WOTS+ chain length
    pub spx_lambda: usize, // security parameter

    // HT and XMSS
    pub spx_h: usize, // total hypertree height
    pub spx_d: usize, // number of layers of XMSS trees in the hypertree

    // PORS+FP
    pub spx_mmax: usize, // maximum number of PORS+FP secret key values in a signature
    pub spx_t: usize,    // total number of PORS+FP tree secret-key leaves
    pub spx_k: usize,    // number of PORS+FP secret-key leaves revealed for a signature

}

// helper function
pub const fn floor_log2(x: usize) -> usize {
    usize::BITS as usize - 1 - x.leading_zeros() as usize
}

// helper function
pub const fn ceil_log2(x: usize) -> usize {
    if x <= 1 { 0 } else { usize::BITS as usize - (x-1).leading_zeros() as usize }
}

// helper function
pub const fn ceil_log4(x: usize) -> usize {
    // ceil(log4 x) = ceil(ceil(log2 x) / 2)
    (ceil_log2(x) + 1) / 2
}

// helper function
pub const fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

impl SphincsvParams {

    // SPHINCS+V parameters

    pub const fn spx_skbytes(&self) -> usize {
        4*self.spx_n // 4 * SPX_N
    }

    pub const fn spx_pkbytes(&self) -> usize {
        2*self.spx_n // 2 * SPX_N
    }

    pub const fn spx_m(&self) -> usize {
        self.spx_md_len() + self.spx_idx_tree_len() + self.spx_idx_leaf_len()
    }

    pub const fn spx_md_len(&self) -> usize {
        self.spx_n
    }

    pub const fn spx_idx_tree_len(&self) -> usize {
        ceil_div(self.spx_h - self.spx_h_prime(), 8) // ceil((SPX_H - SPX_H_PRIME) / 8)
    }

    pub const fn spx_idx_leaf_len(&self) -> usize {
        ceil_div(self.spx_h_prime(), 8) // ceil((SPX_H_PRIME) / 8)
    }

    // WOTS+ parameters

    pub const fn spx_w(&self) -> usize {
        1 << self.spx_lg_w // 2^SPX_LG_W
    }

    pub const fn spx_v(&self) -> usize {
        let mut v = 1;
        loop {
            // w^v > 2^(lambda + log4 lambda)  <=>  2*v*lg_w > 2*lambda + log2(lambda)
            let feasible = 2 * v * self.spx_lg_w > 2 * self.spx_lambda + ceil_log2(self.spx_lambda);
            if feasible {
                if let Some(_) = d0_for(self.spx_lg_w, v, self.spx_lambda) {
                    return v;
                }
            }
            v += 1;
        }
    }

    pub const fn spx_d0(&self) -> usize {
        // find the minimum hypercube layer d0 such that l_d0 >= 2^lambda
        match d0_for(self.spx_lg_w, self.spx_v(), self.spx_lambda) {
            Some(d) => d,
            None => panic!("no layer with >= 2^lambda vertices"),
        }
    }

    // HT and XMSS parametes

    pub const fn spx_h_prime(&self) -> usize {
        self.spx_h / self.spx_d // SPX_H / SPX_D
    }

    pub const fn xmss_tree_size(&self) -> usize {
        (1 << (self.spx_h_prime() + 1)) - 1 // 2^(SPX_H_PRIME+1)-1
    }

    // PORS+FP parameters

    // height of the PORS+FP tree
    pub const fn spx_h_bar(&self) -> usize {
        ceil_log2(self.spx_t) // ceil(log_2(SPX_T))
    }

    // number of nodes in a PORS tree (without the forced pruning)
    pub const fn pors_tree_size(&self) -> usize {
        (1 << (self.spx_h_bar() + 1)) - 1 // 2^(spx_h_bar+1)-1
    }

    // signature component byte lengths

    pub const fn wots_sig(&self) -> usize {
        self.spx_v() * self.spx_n // SPX_V * SPX_N
    }

    pub const fn xmss_sig(&self) -> usize {
        self.wots_sig() + self.spx_h_prime() * self.spx_n // WOTS_SIG + SPX_H_PRIME*SPX_N
    }

    pub const fn ht_sig(&self) -> usize {
        self.spx_d * self.xmss_sig() // SPX_D * XMSS_SIG
    }

    pub const fn porsfp_sig(&self) -> usize {
        4 + self.spx_k*self.spx_n + self.spx_mmax*self.spx_n // u32 + (SPX_K*SPX_N) + (SPX_M_MAX*SPX_N)
    }

    pub const fn spx_sig(&self) -> usize {
        self.spx_n + self.porsfp_sig() + self.ht_sig() // SPX_N + PORS_SIG + HT_SIG
    }
    
}

