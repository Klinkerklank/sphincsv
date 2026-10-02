
pub const PARAMS: SphincsvParams = SphincsvParams {

    // security parameter
    n: 16,

    // WOTS+
    lg_w: 4,

    // HT and XMSS
    h: 66,
    d: 22,

    // FORS
    a: 6,
    k: 33,

};

pub struct SphincsvParams {

    // security parameter
    pub n: usize,

    // WOTS+
    pub lg_w: usize,

    // HT and XMSS
    pub h: usize,
    pub d: usize,

    // FORS
    pub a: usize,
    pub k: usize,

}

// helper function
pub const fn floor_log2(x: usize) -> usize {
    usize::BITS as usize - 1 - x.leading_zeros() as usize
}

// helper function
pub const fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

impl SphincsvParams {

    // SPHINCS+ parameters

    pub const fn spx_skbytes(&self) -> usize {
        4*self.n // 4 * SPX_N
    }

    pub const fn spx_pkbytes(&self) -> usize {
        2*self.n // 2 * SPX_N
    }

    pub const fn m(&self) -> usize {
        ceil_div(self.k * self.a, 8)
            + ceil_div(self.h - self.spx_h_prime(), 8)
            + ceil_div(self.spx_h_prime(), 8)
    }

    pub const fn spx_md_len(&self) -> usize {
        (self.k * self.a + 7) / 8 // ceil((SPX_K * SPX_A) / 8)
    }

    pub const fn spx_idx_tree_len(&self) -> usize {
        (self.h - self.spx_h_prime() + 7) / 8 // ceil((SPX_H - SPX_H_PRIME) / 8)
    }

    pub const fn spx_idx_leaf_len(&self) -> usize {
        (self.spx_h_prime() + 7) / 8 // ceil((SPX_H_PRIME) / 8)
    }

    // WOTS+ parameters

    pub const fn spx_w(&self) -> usize {
        1 << self.lg_w // 2^SPX_LG_W
    }

    pub const fn spx_len_1(&self) -> usize {
        (8 * self.n + self.lg_w - 1) / self.lg_w // ceil(8*SPX_N / SPX_LG_W)
    }

    pub const fn spx_len_2(&self) -> usize {
        // floor(log2(SPX_LEN_1 * (SPX_W - 1)) / SPX_LG_W) + 1
        let x = self.spx_len_1() * (self.spx_w() - 1);
        floor_log2(x) / self.lg_w + 1
    }

    pub const fn spx_len(&self) -> usize {
        self.spx_len_1() + self.spx_len_2() // SPX_LEN_1 + SPX_LEN_2
    }

    // HT and XMSS parametes

    pub const fn spx_h_prime(&self) -> usize {
        self.h / self.d // SPX_H / SPX_D
    }

    pub const fn xmss_tree_size(&self) -> usize {
        (1 << (self.spx_h_prime() + 1)) - 1 // 2^(SPX_H_PRIME+1)-1
    }

    // FORS parameters

    pub const fn spx_t(&self) -> usize {
        1 << self.a // 2^SPX_A
    }

    pub const fn fors_tree_size(&self) -> usize {
        (1 << (self.a + 1)) - 1 // 2^(SPX_A+1)-1
    }

    // signature component byte lengths

    pub const fn wots_sig(&self) -> usize {
        self.spx_len() * self.n // SPX_LEN * SPX_N
    }

    pub const fn xmss_sig(&self) -> usize {
        self.wots_sig() + self.spx_h_prime() * self.n // WOTS_SIG + SPX_H_PRIME*SPX_N
    }

    pub const fn ht_sig(&self) -> usize {
        self.d * self.xmss_sig() // SPX_D * XMSS_SIG
    }

    pub const fn fors_sig(&self) -> usize {
        self.k * (1 + self.a) * self.n // SPX_K * (1 + SPX_A) * SPX_N
    }

    pub const fn spx_sig(&self) -> usize {
        self.n + self.fors_sig() + self.ht_sig() // SPX_N + FORS_SIG + HT_SIG
    }
    
}

// SPHINCS+ parameters
pub const SPX_M: usize = 34; // ceil((SPX_K * SPX_A) / 8) + ceil((SPX_H - SPX_H_PRIME) / 8) + ceil((SPX_H_PRIME) / 8)

// ADRS type field values
pub mod adrs_type {
    pub const WOTS_HASH: u32  = 0;
    pub const WOTS_PK: u32    = 1;
    pub const TREE: u32       = 2;
    pub const FORS_TREE: u32  = 3;
    pub const FORS_ROOTS: u32 = 4;
    pub const WOTS_PRF: u32   = 5;
    pub const FORS_PRF: u32   = 6;
}