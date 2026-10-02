
// SPHINCS+ parameters
pub const SPX_N: usize = 16;
pub const SPX_M: usize = 34; // ceil((SPX_K * SPX_A) / 8) + ceil((SPX_H - SPX_H_PRIME) / 8) + ceil((SPX_H_PRIME) / 8)
pub const SPX_SKBYTES: usize = 64; // 4 * SPX_N
pub const SPX_PKBYTES: usize = 32; // 2 * SPX_N
pub const SPX_MD_LEN: usize = 25; // ceil((SPX_K * SPX_A) / 8)
pub const SPX_IDX_TREE_LEN: usize = 8; // ceil((SPX_H - SPX_H_PRIME) / 8)
pub const SPX_IDX_LEAF_LEN: usize = 1; // ceil((SPX_H_PRIME) / 8)

// WOTS+ parameters
pub const SPX_LG_W: usize  = 4;
pub const SPX_W: usize     = 16; // 2^SPX_LG_W
pub const SPX_LEN_1: usize = 32; // ceil(8*SPX_N / SPX_LG_W)
pub const SPX_LEN_2: usize = 3; // floor(log2(SPX_LEN_1 * (SPX_W - 1)) / SPX_LG_W) + 1
pub const SPX_LEN: usize   = 35; // SPX_LEN_1 + SPX_LEN_2

// hypertree and XMSS parameters
pub const SPX_H: usize       = 66;
pub const SPX_D: usize       = 22;
pub const SPX_H_PRIME: usize = 3; // SPX_H / SPX_D
pub const XMSS_TREE_SIZE: usize = 15; // 2^(SPX_H_PRIME+1)-1

// FORS parameters
pub const SPX_A: usize = 6;
pub const SPX_K: usize = 33;
pub const SPX_T: usize = 64; // 2^SPX_A
pub const FORS_TREE_SIZE: usize = 127; // 2^(SPX_A+1)-1

// Signature lengths
// WOTS_SIG = one SPX_N-byte signature value for each of the SPX_LEN chains
pub const WOTS_SIG: usize = 560; // SPX_LEN * SPX_N
// XMSS_SIG = one WOTS+ signature followed by an SPX_H_PRIME-length authentication path
pub const XMSS_SIG: usize = 608; // WOTS_SIG + SPX_H_PRIME*SPX_N
// HT_SIG = one XMSS signature for each of the SPX_D layers in the hypertree
pub const HT_SIG: usize   = 13376; // SPX_D * XMSS_SIG
// FORS_SIG = for each of the SPX_K trees in a FORS forest, one SPX_N-byte secret value followed by an SPX_A-length authentication path
pub const FORS_SIG: usize = 3696; // SPX_K * (1 + SPX_A) * SPX_N
// SPX_SIG = an SPX_N-byte message randomiser follwed by one FORS signature and one hypertree signature
pub const SPX_SIG: usize  = 17088; // SPX_N + FORS_SIG + HT_SIG

// ADRS constant values for the type field
pub const SPX_ADRS_TYPE_WOTS_HASH: usize  = 0;
pub const SPX_ADRS_TYPE_WOTS_PK: usize    = 1;
pub const SPX_ADRS_TYPE_TREE: usize       = 2;
pub const SPX_ADRS_TYPE_FORS_TREE: usize  = 3;
pub const SPX_ADRS_TYPE_FORS_ROOTS: usize = 4;
pub const SPX_ADRS_TYPE_WOTS_PRF: usize   = 5;
pub const SPX_ADRS_TYPE_FORS_PRF: usize   = 6;

// SHA2 parameters
pub const SHA256_IN: usize  = 64;
pub const SHA256_OUT: usize = 32;
pub const SHA256_ROUNDS_NUM: usize = 64;
pub const SHA256_STATE_WORD_SIZE: usize = 8;

