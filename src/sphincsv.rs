/*
 * SPHINCS+V top-level functions
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::params::{N, H, D, H_PRIME_LO, H_PRIME_HI, M, MD_LEN, IDX_TREE_LEN, IDX_LEAF_LEN, SKBYTES, PKBYTES, PORS_SIG, HT_SIG, SPXV_SIG}; // parameter values

use crate::tweakable_hashes::{prf_msg, h_msg}; // hash function instantiations

use crate::porsfp::{porsfp_sign, porsfp_pkfromsig}; // PORS+FP implementation
use crate::xmss::{xmss_node};                       // XMSS implementation
use crate::ht::{ht_sign, ht_verify};                // HT implementation

use rand::RngExt; // for getting random keying material

/////////////////////// HELPER FUNCTIONS ///////////////////////

fn parse_indices(
    tmp_idx_tree: [u8; IDX_TREE_LEN], // raw tree index data
    tmp_idx_leaf: [u8; IDX_LEAF_LEN], // raw leaf index data
) -> ([u32; 3], u32) {

    // initialise idx_tree to 0
    let mut idx_tree: [u32; 3] = [0u32; 3];

    // convert the byte string into a u32 array
    for i in 0..IDX_TREE_LEN {

        // shift the reference word left by eight bits, and insert the leftmost byte of the word to the right
        idx_tree[0] = (idx_tree[0] << 8) | (idx_tree[1] >> 24);

        // shift the reference word left by eight bits, and insert the leftmost byte of the word to the right
        idx_tree[1] = (idx_tree[1] << 8) | (idx_tree[2] >> 24);

        // shift the reference word left by eight bits, and insert the next byte from the input
        idx_tree[2] = (idx_tree[2] << 8) | (tmp_idx_tree[i] as u32);

    }

    // compute idx_tree mod 2^(h-h'):
    // since the mod is a power of two, computing the mod result is the same as performing
    // an AND with a bitmask where the least-significant H-H_PRIME_LO bits are 1
    if H-H_PRIME_LO <= 32 {
        idx_tree[0] = 0;
        idx_tree[1] = 0;
        idx_tree[2] &= (1 << (H-H_PRIME_LO)) - 1;
    } else if H-H_PRIME_LO <= 64 {
        idx_tree[0] = 0;
        idx_tree[1] &= (1 << (H-H_PRIME_LO-32)) - 1;
    } else { // H-H_PRIME_LO <= 96
        idx_tree[0] &= (1 << (H-H_PRIME_LO-64)) - 1;
    }

    // initialise idx_leaf to 0
    let mut idx_leaf: u32 = 0;

    for i in 0..IDX_LEAF_LEN {
        // shift the word left by eight bits to make place for one byte,
        // and insert the next byte in those last eight bit positions
        idx_leaf = (idx_leaf << 8) | (tmp_idx_leaf[i] as u32);
    }

    // compute idx_leaf mod 2^(h'):
    // since the mod is a power of two, computing the mod result is the same as performing
    // an AND with a bitmask where the least-significant h-h' bits are 1
    idx_leaf &= (1 << H_PRIME_LO) - 1;

    (idx_tree, idx_leaf)
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 18 FROM SLH-DSS (FIPS 205)                         |
| Generates a SPHINCS+V key pair.                              |
+-------------------------------------------------------------*/
fn sphincsv_keygen_internal(
    keyrnd: &[u8; 3*N], // key randomness
) -> ([u8; SKBYTES], [u8; PKBYTES]) {

    let mut sk: [u8; SKBYTES] = [0u8; SKBYTES]; // secret key = [SK.seed, SK.prf, PK.seed, PK.root]
    let mut pk: [u8; PKBYTES] = [0u8; PKBYTES]; // public key =                  [PK.seed, PK.root]

    // copy SK.seed, SK.prf, and PK.seed from the given key randomness to SK
    sk[0..3*N].copy_from_slice(&keyrnd[0..3*N]);

    // copy PK.seed from the given key randomness to PK
    pk[0..N].copy_from_slice(&keyrnd[2*N..3*N]);

    // separate the secret key components needed later
    let mut sk_seed: [u8; N] = [0u8; N];
    let mut pk_seed: [u8; N] = [0u8; N];
    sk_seed.copy_from_slice(&sk[0*N..1*N]);
    pk_seed.copy_from_slice(&sk[2*N..3*N]);

    // initialise ADRS
    let mut adrs: Adrs = Adrs::new();

    // set the layer address to the highest hypertree layer
    adrs.set_layer_addr(D as u32 - 1);

    // compute PK.root, which is the node in the top-most XMSS tree at
    // horizontal index i = 0 and height z = H_PRIME_HI
    let i: u32 = 0u32;
    let z: u32 = H_PRIME_HI as u32;
    let pk_root: [u8; N] = xmss_node(&sk_seed, i, z, &pk_seed, adrs, H_PRIME_HI);

    // copy PK.root to SK and PK
    sk[3*N..4*N].copy_from_slice(&pk_root);
    pk[1*N..2*N].copy_from_slice(&pk_root);

    (sk, pk)
}

/*-------------------------------------------------------------+
| ALGORITHM 21 FROM SLH-DSS (FIPS 205)                         |
| Generates a SPHINCS+V key pair.                              |
| Generates the randomness for sphincsv_keygen_internal.       |
+-------------------------------------------------------------*/
pub fn sphincsv_keygen() -> ([u8; SKBYTES], [u8; PKBYTES]) {

    // get a random number generator
    let mut rng: rand::prelude::ThreadRng = rand::rng();

    // generate the key randomness
    let keyrnd: [u8; 3*N] = rng.random();

    // generate a SPHINCS+V key pair
    let (sk, pk) = sphincsv_keygen_internal(&keyrnd);

    (sk, pk)
}

/*-------------------------------------------------------------+
| ALGORITHM 19 FROM SLH-DSS (FIPS 205)                         |
| Generates a SPHINCS+V signature.                             |
+-------------------------------------------------------------*/
fn sphincsv_sign_internal(
    context: &[u8],     // context string
    message: &[u8],     // message string
    sk: &[u8; SKBYTES], // secret key
    addrnd: &[u8; N],   // additional randomness
) -> [u8; SPXV_SIG] {

    // declare the SPHINCS+V signature
    let mut sig_sphincsv: [u8; SPXV_SIG] = [0u8; SPXV_SIG];

    // separate the secret key components
    let mut sk_seed: [u8; N] = [0u8; N];
    let mut sk_prf:  [u8; N] = [0u8; N];
    let mut pk_seed: [u8; N] = [0u8; N];
    let mut pk_root: [u8; N] = [0u8; N];
    sk_seed.copy_from_slice(&sk[0*N..1*N]);
    sk_prf .copy_from_slice(&sk[1*N..2*N]);
    pk_seed.copy_from_slice(&sk[2*N..3*N]);
    pk_root.copy_from_slice(&sk[3*N..4*N]);

    // compute the message randomiser
    let r: [u8; N] = prf_msg(&sk_prf, &addrnd, &context, &message);

    // write the message randomiser to the signature
    sig_sphincsv[0..N].copy_from_slice(&r);

    // compute the message digest
    let digest: [u8; M] = h_msg(&r, &pk_seed, &pk_root, &context, &message);

    // extract md, tmp_idx_tree, and tmp_idx_leaf from digest
    let mut md:           [u8; MD_LEN]       = [0u8; MD_LEN];
    let mut tmp_idx_tree: [u8; IDX_TREE_LEN] = [0u8; IDX_TREE_LEN];
    let mut tmp_idx_leaf: [u8; IDX_LEAF_LEN] = [0u8; IDX_LEAF_LEN];
    md          .copy_from_slice(&digest[0                     .. MD_LEN                              ]);
    tmp_idx_tree.copy_from_slice(&digest[MD_LEN                .. MD_LEN + IDX_TREE_LEN               ]);
    tmp_idx_leaf.copy_from_slice(&digest[MD_LEN + IDX_TREE_LEN .. MD_LEN + IDX_TREE_LEN + IDX_LEAF_LEN]);

    // compute idx_tree and idx_leaf from tmp_idx_tree and tmp_idx_leaf
    let (idx_tree, idx_leaf) = parse_indices(tmp_idx_tree, tmp_idx_leaf);

    // initialise ADRS
    let mut adrs: Adrs = Adrs::new();

    // set the ADRS values for the PORS+FP signature generation
    adrs.set_tree_addr(idx_tree); // lowest-layer tree index of the XMSS tree that will sign the PORS+FP public key
    adrs.set_type_and_clear(adrs_type::PORS_TREE);
    adrs.set_key_pair_addr(idx_leaf); // leaf index of the XMSS tree that will sign the PORS+FP public key

    // compute the PORS+FP signature
    let sig_porsfp: [u8; PORS_SIG] = porsfp_sign(&md, &sk_seed, &pk_seed, adrs);

    // write the PORS+FP signature to the SPHINCS+V signature
    sig_sphincsv[N..N+PORS_SIG].copy_from_slice(&sig_porsfp);

    // compute the PORS+FP public key based on the PORS+FP signature
    let pk_porsfp: [u8; N] = porsfp_pkfromsig(&sig_porsfp, &md, &pk_seed, adrs);

    // compute the hypertree signature on the PORS+FP public key
    let sig_ht: [u8; HT_SIG] = ht_sign(&pk_porsfp, &sk_seed, &pk_seed, idx_tree, idx_leaf);

    // write the PORS+FP signature to the SPHINCS+V signature
    sig_sphincsv[N+PORS_SIG..N+PORS_SIG+HT_SIG].copy_from_slice(&sig_ht);

    sig_sphincsv
}

/*-------------------------------------------------------------+
| ALGORITHM 22 FROM SLH-DSS (FIPS 205)                         |
| Generates a pure SPHINCS+V signature.                        |
| Generates the randomness needed for sphincsv_sign_internal   |
+-------------------------------------------------------------*/
pub fn sphincsv_sign (
    context: &[u8],      // context string
    message: &[u8],      // message string
    sk: &[u8; SKBYTES],  // secret key
    deterministic: bool, // whether to use addrnd = PK.seed (else addrnd = randombytes)
) -> [u8; SPXV_SIG] {

    // assert that the context string is not too long
    assert!(context.len() <= 255, "\x1b[1;91mContext string length of {} does not satisfy {} <= 255\x1b[0m", context.len(), context.len());

    // declare the additional randomness
    let mut addrnd: [u8; N] = [0u8; N];

    if deterministic {

        addrnd.copy_from_slice(&sk[2*N..3*N]);

    } else {

        // get a random number generator
        let mut rng: rand::prelude::ThreadRng = rand::rng();

        // generate the additional randomness
        addrnd = rng.random();

    }

    let sig_sphincsv: [u8; SPXV_SIG] = sphincsv_sign_internal(&context, &message, &sk, &addrnd);

    sig_sphincsv
}

/*-------------------------------------------------------------+
| ALGORITHM 20 FROM SLH-DSS (FIPS 205)                         |
| Verifies a SPHINCS+V signature.                              |
+-------------------------------------------------------------*/
fn sphincsv_verify_internal(
    context: &[u8],                // context string
    message: &[u8],                // message string
    sig_sphincsv: &[u8; SPXV_SIG], // SPHINCS+V signature
    pk: &[u8; PKBYTES],            // public key
) -> bool {

    // separate the public key components
    let mut pk_seed: [u8; N] = [0u8; N];
    let mut pk_root: [u8; N] = [0u8; N];
    pk_seed.copy_from_slice(&pk[0*N..1*N]);
    pk_root.copy_from_slice(&pk[1*N..2*N]);
    
    // extract the message randomiser r from the overall signature
    let mut r: [u8; N] = [0u8; N];
    r.copy_from_slice(&sig_sphincsv[0..N]);

    // compute the message digest
    let digest: [u8; M] = h_msg(&r, &pk_seed, &pk_root, &context, &message);

    // extract md, tmp_idx_tree, and tmp_idx_leaf from digest
    let mut md:           [u8; MD_LEN]       = [0u8; MD_LEN];
    let mut tmp_idx_tree: [u8; IDX_TREE_LEN] = [0u8; IDX_TREE_LEN];
    let mut tmp_idx_leaf: [u8; IDX_LEAF_LEN] = [0u8; IDX_LEAF_LEN];
    md          .copy_from_slice(&digest[0                     .. MD_LEN                              ]);
    tmp_idx_tree.copy_from_slice(&digest[MD_LEN                .. MD_LEN + IDX_TREE_LEN               ]);
    tmp_idx_leaf.copy_from_slice(&digest[MD_LEN + IDX_TREE_LEN .. MD_LEN + IDX_TREE_LEN + IDX_LEAF_LEN]);

    // compute idx_tree and idx_leaf from tmp_idx_tree and tmp_idx_leaf
    let (idx_tree, idx_leaf) = parse_indices(tmp_idx_tree, tmp_idx_leaf);

    // initialise ADRS
    let mut adrs: Adrs = Adrs::new();
    
    // set the ADRS values for the PORS+FP signature generation
    adrs.set_tree_addr(idx_tree);     // lowest-layer tree index of the XMSS tree that will sign the PORS+FP public key
    adrs.set_type_and_clear(adrs_type::PORS_TREE);
    adrs.set_key_pair_addr(idx_leaf); // Leaf index of the XMSS tree that will sign the PORS+FP public key
    
    // extract the PORS+FP signature from the overall signature
    let mut sig_porsfp: [u8; PORS_SIG] = [0u8; PORS_SIG];
    sig_porsfp.copy_from_slice(&sig_sphincsv[N .. N + PORS_SIG]);
    
    // compute the PORS+FP public key based on the PORS+FP signature
    let pk_porsfp: [u8; N] = porsfp_pkfromsig(&sig_porsfp, &md, &pk_seed, adrs);
    
    // extract the HT signature from the overall signature
    let mut sig_ht: [u8; HT_SIG] = [0u8; HT_SIG];
    sig_ht.copy_from_slice(&sig_sphincsv[N + PORS_SIG .. N + PORS_SIG + HT_SIG]);

    // verify the hypertree signature on the PORS+FP public key
    let res: bool = ht_verify(&pk_porsfp, &sig_ht, &pk_seed, idx_tree, idx_leaf, &pk_root);

    res
}

/*-------------------------------------------------------------+
| ALGORITHM 24 FROM SLH-DSS (FIPS 205)                         |
| Verifies a pure SPHINCS+V signature.                         |
+-------------------------------------------------------------*/
pub fn sphincsv_verify(
    context: &[u8],                // context string
    message: &[u8],                // message string
    sig_sphincsv: &[u8; SPXV_SIG], // SPHINCS+V signature
    pk: &[u8; PKBYTES],            // public key
) -> bool {

    // assert that the context string is not too long
    assert!(context.len() <= 255, "\x1b[1;91mContext string length of {} does not satisfy {} <= 255\x1b[0m", context.len(), context.len());

    let res: bool = sphincsv_verify_internal(&context, &message, &sig_sphincsv, &pk);

    res
}
