/*
 * HT algorithms, based on:
 * [QSZ26] Qin, Z., Sun, S. and Zheng, F., 'Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths', Oct 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-16 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs; // ADRS data structure

use crate::params::{N, H_PRIME_LO, H_PRIME_HI, D_LO, D_HI, XMSS_LO_SIG, XMSS_HI_SIG, HT_SIG}; // parameter values

use crate::xmss::{xmss_pkfromsig, xmss_lo_sign, xmss_hi_sign}; // XMSS implementation

/////////////////////// HELPER FUNCTIONS ///////////////////////

fn ht_update_idx_lo(
    mut idx_tree: [u32; 3], // index of the tree within the layer of XMSS trees
) -> (u32, [u32; 3]) { // -> idx_leaf, idx_tree

    // idx_leaf = idx_tree mod 2^h':
    // just taking idx_leaf = idx_tree[2] % 2^H_PRIME_LO is fine only if H_PRIME_LO <= 32
    // (which is the case in all approved parameter sets in the SLH-DSS)
    let idx_leaf = idx_tree[2] & ((1 << H_PRIME_LO)-1);

    // idx_tree >>= H_PRIME_LO
    idx_tree[2] = (idx_tree[2] >> H_PRIME_LO) | (idx_tree[1] << 32-H_PRIME_LO);
    idx_tree[1] = (idx_tree[1] >> H_PRIME_LO) | (idx_tree[0] << 32-H_PRIME_LO);
    idx_tree[0] >>= H_PRIME_LO;

    (idx_leaf, idx_tree)
}

fn ht_update_idx_hi(
    mut idx_tree: [u32; 3], // index of the tree within the layer of XMSS trees
) -> (u32, [u32; 3]) { // -> idx_leaf, idx_tree

    // idx_leaf = idx_tree mod 2^h':
    // just taking idx_leaf = idx_tree[2] % 2^H_PRIME_HI is fine only if H_PRIME_HI <= 32
    // (which is the case in all approved parameter sets in the SLH-DSS)
    let idx_leaf = idx_tree[2] & ((1 << H_PRIME_HI)-1);

    // idx_tree >>= H_PRIME_HI
    idx_tree[2] = (idx_tree[2] >> H_PRIME_HI) | (idx_tree[1] << 32-H_PRIME_HI);
    idx_tree[1] = (idx_tree[1] >> H_PRIME_HI) | (idx_tree[0] << 32-H_PRIME_HI);
    idx_tree[0] >>= H_PRIME_HI;

    (idx_leaf, idx_tree)
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 12 FROM SLH-DSS (FIPS 205)                         |
| Generates a hypertree signature.                             |
+-------------------------------------------------------------*/
pub fn ht_sign(
    pk_porsfp: &[u8; N], // message to sign (PORS+FP public key)
    sk_seed: &[u8; N],   // SK.seed: secret seed
    pk_seed: &[u8; N],   // PK.seed: public seed
    tree: [u32; 3],      // lowest-layer XMSS tree index
    leaf: u32,           // XMSS tree leaf index
) -> [u8; HT_SIG] // -> sig_ht
{

    // initialise the hypertree signature
    let mut sig_ht: [u8; HT_SIG] = [0u8; HT_SIG];

    // copy the given tree and leaf indices
    let mut idx_leaf: u32 = leaf;
    let mut idx_tree: [u32; 3] = tree;

    // initialise ADRS with the tree index
    let mut adrs: Adrs = Adrs::new();
    adrs.set_tree_addr(idx_tree);

    // compute the lowest-layer XMSS signature on the PORS+FP public key
    let sig_lo_xmss: [u8; XMSS_LO_SIG] = xmss_lo_sign(&pk_porsfp, &sk_seed, idx_leaf, &pk_seed, adrs);

    // store the XMSS signature in the hypertree signature
    sig_ht[0..XMSS_LO_SIG].copy_from_slice(&sig_lo_xmss);

    // compute the lowest-layer XMSS tree root based on the first XMSS signature
    let mut root: [u8; N] = xmss_pkfromsig(idx_leaf, &sig_lo_xmss, &pk_porsfp, &pk_seed, adrs, H_PRIME_LO);
    let mut root_prev: [u8; N] = [0u8; N]; // setup for in the loop

    // iteratively compute the short XMSS signatures that sign the root of the previous XMSS tree
    for i in 1..D_LO {

        // update indices:
        // -> idx_leaf = idx_tree mod 2^h'
        // -> idx_tree >>= h'
        (idx_leaf, idx_tree) = ht_update_idx_lo(idx_tree);

        // set the current layer and tree addresses in ADRS
        adrs.set_layer_addr(i as u32);
        adrs.set_tree_addr(idx_tree);
        
        // copy the root of the previous XMSS tree
        root_prev.copy_from_slice(&root);
        
        // compute the XMSS signature on the previous XMSS tree's root
        let sig_xmss: [u8; XMSS_LO_SIG] = xmss_lo_sign(&root_prev, &sk_seed, idx_leaf, &pk_seed, adrs);

        // store the XMSS signature in the hypertree signature
        sig_ht[i*XMSS_LO_SIG..(i+1)*XMSS_LO_SIG].copy_from_slice(&sig_xmss);

        // compute the current XMSS tree's root
        root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &root_prev, &pk_seed, adrs, H_PRIME_LO));

    }

    // iteratively compute the tall XMSS signatures that sign the root of the previous XMSS tree
    for i in 0..D_HI {

        // update indices:
        // -> idx_leaf = idx_tree mod 2^h'
        // -> idx_tree >>= h'
        (idx_leaf, idx_tree) = ht_update_idx_hi(idx_tree);

        // set the current layer and tree addresses in ADRS
        adrs.set_layer_addr((D_LO + i) as u32);
        adrs.set_tree_addr(idx_tree);
        
        // copy the root of the previous XMSS tree
        root_prev.copy_from_slice(&root);
        
        // compute the XMSS signature on the previous XMSS tree's root
        let sig_xmss: [u8; XMSS_HI_SIG] = xmss_hi_sign(&root_prev, &sk_seed, idx_leaf, &pk_seed, adrs);

        // store the XMSS signature in the hypertree signature
        // (accounting for the previous lower-height XMSS signatures)
        sig_ht[D_LO*XMSS_LO_SIG + i*XMSS_HI_SIG .. D_LO*XMSS_LO_SIG + (i+1)*XMSS_HI_SIG].copy_from_slice(&sig_xmss);

        // compute the current XMSS tree's root
        root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &root_prev, &pk_seed, adrs, H_PRIME_HI));

    }

    sig_ht
}

/*-------------------------------------------------------------+
| ALGORITHM 13 FROM SLH-DSS (FIPS 205)                         |
| Verifies a hypertree signature.                              |
+-------------------------------------------------------------*/
pub fn ht_verify(
    pk_porsfp: &[u8; N],   // message to verify signature on (PORS+FP public key)
    sig_ht: &[u8; HT_SIG], // HT signature
    pk_seed: &[u8; N],     // PK.seed: public seed
    tree: [u32; 3],        // lowest-layer XMSS tree index
    leaf: u32,             // XMSS tree leaf index
    pk_root: &[u8; N],     // PK.root: hypertree root
) -> bool // -> whether the HT signature is correct w.r.t. PK.root
{

    // copy the given tree and leaf indices
    let mut idx_leaf: u32 = leaf;
    let mut idx_tree: [u32; 3] = tree;

    // initialise ADRS with the tree index
    let mut adrs: Adrs = Adrs::new();
    adrs.set_tree_addr(idx_tree);

    // extract the first XMSS signature from the hypertree signature
    let mut sig_xmss: [u8; XMSS_LO_SIG] = [0u8; XMSS_LO_SIG];
    sig_xmss.copy_from_slice(&sig_ht[0..XMSS_LO_SIG]);
    
    // compute the lowest-layer XMSS tree root based on the first XMSS signature
    let mut root: [u8; N] = [0u8; N];
    root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &pk_porsfp, &pk_seed, adrs, H_PRIME_LO));
    let mut root_prev: [u8; N] = [0u8; N]; // setup for in the loop

    // compute the roots of the short XMSS trees
    for i in 1..D_LO {

        // update indices:
        // -> idx_leaf = idx_tree mod 2^h'
        // -> idx_tree >>= h'
        (idx_leaf, idx_tree) = ht_update_idx_lo(idx_tree);

        // set the current layer and tree addresses in ADRS
        adrs.set_layer_addr(i as u32);
        adrs.set_tree_addr(idx_tree);
        
        // copy the root of the previous XMSS tree
        root_prev.copy_from_slice(&root);

        // extract the XMSS signature on the previous XMSS tree's root
        sig_xmss.copy_from_slice(&sig_ht[i*XMSS_LO_SIG..(i+1)*XMSS_LO_SIG]);

        // compute the current XMSS tree's root
        root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &root_prev, &pk_seed, adrs, H_PRIME_LO));

    }

    // rescale the XMSS signature buffer for the tall XMSS trees
    let mut sig_xmss: [u8; XMSS_HI_SIG] = [0u8; XMSS_HI_SIG];

    // compute the roots of the tall XMSS trees
    for i in 0..D_HI {

        // update indices:
        // -> idx_leaf = idx_tree mod 2^h'
        // -> idx_tree >>= h'
        (idx_leaf, idx_tree) = ht_update_idx_hi(idx_tree);

        // set the current layer and tree addresses in ADRS
        adrs.set_layer_addr((D_LO + i) as u32);
        adrs.set_tree_addr(idx_tree);
        
        // copy the root of the previous XMSS tree
        root_prev.copy_from_slice(&root);

        // extract the XMSS signature on the previous XMSS tree's root
        sig_xmss.copy_from_slice(&sig_ht[D_LO*XMSS_LO_SIG + i*XMSS_HI_SIG .. D_LO*XMSS_LO_SIG + (i+1)*XMSS_HI_SIG]);

        // compute the current XMSS tree's root
        root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &root_prev, &pk_seed, adrs, H_PRIME_HI));

    }

    // compare the computed hypertree root and the claimed PK.root
    let res: bool = pk_root == &root;

    res
}
