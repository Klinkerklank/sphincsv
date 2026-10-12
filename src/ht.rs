// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * HT algorithms, based on:
 * [QSZ26] Qin, Z., Sun, S. and Zheng, F., 'Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths', Oct 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::params::PARAMS;  // the SPHINCS+V parameters
use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type;
use crate::xmss::xmss_pkfromsig;
use crate::xmss::xmss_sign; // ADRS type constants

/////////////////////// HELPER FUNCTIONS ///////////////////////

fn ht_update_idx(
    mut idx_tree: [u32; 3], // index of the tree within the layer of XMSS trees
) -> (u32, [u32; 3]) { // -> idx_leaf, idx_tree

    // idx_leaf = idx_tree mod 2^h':
    // just taking idx_leaf = idx_tree[2] % 2^SPX_H_PRIME is fine only if SPX_H_PRIME <= 32
    // (which is the case in all approved parameter sets in the SLH-DSS)
    let idx_leaf = idx_tree[2] & ((1 << PARAMS.spx_h_prime())-1);

    // idx_tree >>= SPX_H_PRIME
    idx_tree[2] = (idx_tree[2] >> PARAMS.spx_h_prime()) | (idx_tree[1] << 32-PARAMS.spx_h_prime());
    idx_tree[1] = (idx_tree[1] >> PARAMS.spx_h_prime()) | (idx_tree[0] << 32-PARAMS.spx_h_prime());
    idx_tree[0] >>= PARAMS.spx_h_prime();

    (idx_leaf, idx_tree)
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 12 FROM SLH-DSS (FIPS 205)                         |
| Generates a hypertree signature.                             |
+-------------------------------------------------------------*/
pub fn ht_sign(
    pk_porsfp: &[u8; PARAMS.spx_n], // message to sign (PORS+FP public key)
    sk_seed: &[u8; PARAMS.spx_n],   // SK.seed: secret seed
    pk_seed: &[u8; PARAMS.spx_n],   // PK.seed: public seed
    tree: [u32; 3],                 // lowest-layer XMSS tree index
    leaf: u32,                      // XMSS tree leaf index
) -> [u8; PARAMS.ht_sig()] // -> sig_ht
{

    // initialise the hypertree signature
    let mut sig_ht: [u8; PARAMS.ht_sig()] = [0u8; PARAMS.ht_sig()];

    // copy the given tree and leaf indices
    let mut idx_leaf: u32 = leaf;
    let mut idx_tree: [u32; 3] = [0u32; 3];
    for i in 0..PARAMS.spx_idx_tree_len() { idx_tree[i] = tree[i]; }

    // initialise ADRS with the tree index
    let mut adrs: Adrs = Adrs::new();
    adrs.set_tree_addr(idx_tree);

    // compute the lowest-layer XMSS signature on the PORS+FP public key
    let sig_xmss: [u8; PARAMS.xmss_sig()] = xmss_sign(&pk_porsfp, &sk_seed, idx_leaf, &pk_seed, adrs);

    // store the XMSS signature in the hypertree signature
    sig_ht[0..PARAMS.xmss_sig()].copy_from_slice(&sig_xmss);

    // compute the lowest-layer XMSS tree root based on the first XMSS signature
    let mut root: [u8; PARAMS.spx_n] = xmss_pkfromsig(idx_leaf, &sig_xmss, &pk_porsfp, &pk_seed, adrs);
    let mut root_prev: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n]; // setup for in the loop

    // iteratively compute the XMSS signatures that sign the root of the previous XMSS tree
    for i in 1..PARAMS.spx_d {

        // update indices:
        // -> idx_leaf = idx_tree mod 2^h'
        // -> idx_tree >>= h'
        (idx_leaf, idx_tree) = ht_update_idx(idx_tree);

        // set the current layer and tree addresses in ADRS
        adrs.set_layer_addr(i as u32);
        adrs.set_tree_addr(idx_tree);
        
        // copy the root of the previous XMSS tree
        root_prev.copy_from_slice(&root);
        
        // compute the XMSS signature on the previous XMSS tree's root
        let sig_xmss: [u8; PARAMS.xmss_sig()] = xmss_sign(&root_prev, &sk_seed, idx_leaf, &pk_seed, adrs);

        // store the XMSS signature in the hypertree signature
        sig_ht[i*PARAMS.xmss_sig()..(i+1)*PARAMS.xmss_sig()].copy_from_slice(&sig_xmss);

        // compute the current XMSS tree's root, unless it's the topmost layer
        // in which case the root will be PK.root (which is not part of the signature)
        if i < PARAMS.spx_d-1 {
            root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &root_prev, &pk_seed, adrs));
        }

    }

    sig_ht
}

/*-------------------------------------------------------------+
| ALGORITHM 13 FROM SLH-DSS (FIPS 205)                         |
| Verifies a hypertree signature.                              |
+-------------------------------------------------------------*/
pub fn ht_verify(
    pk_porsfp: &[u8; PARAMS.spx_n], // message to verify signature on (PORS+FP public key)
    sig_ht: &[u8; PARAMS.ht_sig()], // HT signature
    pk_seed: &[u8; PARAMS.spx_n],   // PK.seed: public seed
    tree: [u32; 3],                 // lowest-layer XMSS tree index
    leaf: u32,                      // XMSS tree leaf index
    pk_root: &[u8; PARAMS.spx_n],   // PK.root: hypertree root
) -> bool // -> whether the HT signature is correct w.r.t. PK.root
{

    // copy the given tree and leaf indices
    let mut idx_leaf: u32 = leaf;
    let mut idx_tree: [u32; 3] = [0u32; 3];
    for i in 0..PARAMS.spx_idx_tree_len() { idx_tree[i] = tree[i]; }

    // initialise ADRS with the tree index
    let mut adrs: Adrs = Adrs::new();
    adrs.set_tree_addr(idx_tree);

    // extract the first XMSS signature from the hypertree signature
    let mut sig_xmss: [u8; PARAMS.xmss_sig()] = [0u8; PARAMS.xmss_sig()];
    sig_xmss.copy_from_slice(&sig_ht[0..PARAMS.xmss_sig()]);
    
    // compute the lowest-layer XMSS tree root based on the first XMSS signature
    let mut root: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &pk_porsfp, &pk_seed, adrs));
    let mut root_prev: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n]; // setup for in the loop

    for i in 1..PARAMS.spx_d {

        // update indices:
        // -> idx_leaf = idx_tree mod 2^h'
        // -> idx_tree >>= h'
        (idx_leaf, idx_tree) = ht_update_idx(idx_tree);

        // set the current layer and tree addresses in ADRS
        adrs.set_layer_addr(i as u32);
        adrs.set_tree_addr(idx_tree);
        
        // copy the root of the previous XMSS tree
        root_prev.copy_from_slice(&root);

        // extract the XMSS signature on the previous XMSS tree's root
        sig_xmss.copy_from_slice(&sig_ht[i*PARAMS.xmss_sig()..(i+1)*PARAMS.xmss_sig()]);

        // compute the current XMSS tree's root
        root.copy_from_slice(&xmss_pkfromsig(idx_leaf, &sig_xmss, &root_prev, &pk_seed, adrs));

    }

    // compare the computed hypertree root and the claimed PK.root
    let res: bool = pk_root == &root;

    res
}

