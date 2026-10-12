/*
 * XMSS algorithms
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::params::PARAMS;  // the SPHINCS+V parameters
use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::tweakable_hashes::{h}; // hash function instantiations

use crate::wots::{wots_pkgen, wots_sign, wots_pkfromsig}; // WOTS+ implementation

/////////////////////// HELPER FUNCTIONS ///////////////////////

// compute the left child's coordinates from a given node's (i,z) coordinates
fn lchild(
    // i = horizontal index of the node in the PORS+FP tree
    // z = height of the node in the PORS+FP tree
    (i, z): (u32, u32), // node
) -> (u32, u32) {
    (i<<1, z-1)
}

// compute the byte offset of an spx_n-byte value in the flattened tree
fn flat_tree_idx(
    // i = horizontal index of the node in the PORS+FP tree
    // z = height of the node in the PORS+FP tree
    (i, z): (u32, u32), // node
) -> usize {
    // flat_tree_idx = 2^(h'+1) - 2^(h'+1-z) + i
    ((1 << (PARAMS.spx_h_bar() + 1)) - (1 << (PARAMS.spx_h_bar() + 1 - (z as usize))) + i) as usize
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 9 FROM SLH-DSS (FIPS 205)                          |
| Computes the root of a Merkle subtree of WOTS+ public keys.  |
| (iterative instead of recursive)                             |
+-------------------------------------------------------------*/
pub fn xmss_node(
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    i_target: u32,                // target node index (horizontal)
    z_target: u32,                // target node height
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut adrs: Adrs,               // ADRS
) -> [u8; PARAMS.spx_n] // -> root
{

    // array buffer with enough place to fit the entire (flattened) XMSS tree
    // note that for efficiency only those nodes are computed that are needed
    // to find the target node, so not necessarily the entire buffer is filled
    let mut flat_tree: [u8; PARAMS.xmss_tree_size() * PARAMS.spx_n] = [0u8; PARAMS.xmss_tree_size() * PARAMS.spx_n];

    // iterate over the layers, bottom to top
    for z in 0..z_target+1 {

        let i_start: u32 =  i_target      * (1 << (z_target-z)); //  i_target      * 2^(z_target-z)
        let i_end: u32   = (i_target + 1) * (1 << (z_target-z)); // (i_target + 1) * 2^(z_target-z)

        // iterate over the nodes in a layer, left to right
        for i in i_start..i_end {

            if i == 0 { // layer-0 leaf node: the node value is a WOTS+ public key

                // set the correct values in ADRS for WOTS hashing
                adrs.set_type_and_clear(adrs_type::WOTS_HASH);
                adrs.set_key_pair_addr(i as u32);
                
                // compute the WOTS+ public key
                flat_tree.copy_from_slice(&wots_pkgen(&sk_seed, &pk_seed, adrs));

            } else { // internal node: the node value is the hash of its two children lnode and rnode

                // get the left child
                let mut idx: usize = flat_tree_idx(lchild((i, z))) * PARAMS.spx_n;
                let mut lnode: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
                lnode.copy_from_slice(&flat_tree[idx..idx+PARAMS.spx_n]);

                // get the right child
                idx += PARAMS.spx_n;
                let mut rnode: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
                rnode.copy_from_slice(&flat_tree[idx..idx+PARAMS.spx_n]);

                // compute the relevant ADRS
                adrs.set_type_and_clear(adrs_type::TREE); // set the correct type for computing XMSS internal nodes
                adrs.set_tree_index(i); // set the tree index
                adrs.set_tree_height(z); // set the tree height

                // compute node = H(PK.seed, ADRS, lnode, rnode)
                let node: [u8; PARAMS.spx_n] = h(pk_seed, &adrs, &lnode, &rnode);

                // compute the byte offset of node (i, z) in the flattened tree
                let idx: usize = flat_tree_idx((i, z)) * PARAMS.spx_n;

                // set the internal node in the flattened tree
                flat_tree[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

            }

        }

    }

    // get the root of the subtree at (i_target, z_target)
    let idx: usize = flat_tree_idx((i_target, z_target)) * PARAMS.spx_n; // compute the byte offset of node (i_target, z_target) in the flattened tree
    let mut node: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n]; // declare the subtree root value array
    node.copy_from_slice(&flat_tree[idx..idx+PARAMS.spx_n]); // copy the subtree root from the flattened tree

    node
}

/*-------------------------------------------------------------+
| ALGORITHM 10 FROM SLH-DSS (FIPS 205)                         |
| Generates an XMSS signature.                                 |
+-------------------------------------------------------------*/
pub fn xmss_sign(
    m: &[u8; PARAMS.spx_n],       // message to sign (XMSS public key or FORS public key)
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    idx: u32,                     // WOTS+ leaf index to sign with
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut adrs: Adrs,               // ADRS
) -> [u8; PARAMS.xmss_sig()] // -> sig_xmss
{

    // initialise the XMSS signature
    let mut sig_xmss: [u8; PARAMS.xmss_sig()] = [0u8; PARAMS.xmss_sig()];

    // compute the sibling node's horizontal index
    let mut k: u32 = idx ^ 1;

    // compute and store the authentication path AUTH
    for z in 0..PARAMS.spx_h_prime() {
        
        // compute the sibling node
        let auth_node: [u8; PARAMS.spx_n] = xmss_node(&sk_seed, k, z as u32, &pk_seed, adrs);

        // store the sibling node in the XMSS signature
        sig_xmss[PARAMS.wots_sig()+z*PARAMS.spx_n .. PARAMS.wots_sig()+(z+1)*PARAMS.spx_n].copy_from_slice(&auth_node);
        
        // update the sibling node's horizontal index for the next iteration
        k = (k >> 1) ^ 1;

    }

    // set the correct values in ADRS for WOTS+ hashing
    adrs.set_type_and_clear(adrs_type::WOTS_HASH);
    adrs.set_key_pair_addr(idx);
    
    // compute the WOTS+ signature on the XMSS or PORS+FP public key
    let sig_wots: [u8; PARAMS.wots_sig()] = wots_sign(&m, &sk_seed, &pk_seed, adrs);

    // store the WOTS+ signature in the XMSS signature
    sig_xmss[0..PARAMS.wots_sig()].copy_from_slice(&sig_wots);

    sig_xmss
}

/*-------------------------------------------------------------+
| ALGORITHM 11 FROM SLH-DSS (FIPS 205)                         |
| Computes an XMSS public key from an XMSS signature.          |
+-------------------------------------------------------------*/
pub fn xmss_pkfromsig(
    idx: u32,                           // WOTS+ leaf index to sign with
    sig_xmss: &[u8; PARAMS.xmss_sig()], // XMSS signature
    m: &[u8; PARAMS.spx_n],             // message to sign (XMSS public key or FORS public key)
    pk_seed: &[u8; PARAMS.spx_n],       // PK.seed
    mut adrs: Adrs,                     // ADRS
) -> [u8; PARAMS.spx_n] // -> pk_xmss
{

    // set the correct values in ADRS for WOTS+ hashing
    adrs.set_type_and_clear(adrs_type::WOTS_HASH);
    adrs.set_key_pair_addr(idx);

    // separate the WOTS+ signature from the XMSS signature
    let mut sig_wots: [u8; PARAMS.wots_sig()] = [0u8; PARAMS.wots_sig()];
    sig_wots.copy_from_slice(&sig_xmss[0..PARAMS.wots_sig()]);

    // initialise the node buffers used in the loop
    let mut node0: [u8; PARAMS.spx_n];
    let mut node1: [u8; PARAMS.spx_n];
    let mut buf0: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let mut buf1: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    
    // compute the WOTS+ public key from the WOTS+ signature
    node0 = wots_pkfromsig(&sig_wots, &m, &pk_seed, adrs);

    // set the correct values in ADRS for Merkle tree hashing
    adrs.set_type_and_clear(adrs_type::TREE);
    adrs.set_tree_index(idx);

    for k in 0..PARAMS.spx_h_prime() {

        // set the parent node's height
        adrs.set_tree_height(k as u32 + 1);

        if (idx/(1<<k)) % 2 == 0 { // floor(idx / 2^k) is even
            
            // compute the parent node's horizontal index
            let idx_tree: u32 = adrs.get_tree_index() >> 1;
            
            // set the parent node's tree index
            adrs.set_tree_index(idx_tree);

            // buf = buf0 || buf1 = node0 || AUTH[k]
            buf0.copy_from_slice(&node0);
            buf1.copy_from_slice(&sig_xmss[PARAMS.wots_sig() + k*PARAMS.spx_n .. PARAMS.wots_sig() + (k+1)*PARAMS.spx_n]);

        } else { // floor(idx / 2^k) is odd
            
            // compute the parent node's horizontal index
            let idx_tree: u32 = (adrs.get_tree_index()-1) >> 1;
            
            // set the parent node's tree index
            adrs.set_tree_index(idx_tree);

            // buf = buf0 || buf1 = AUTH[k] || node0
            buf0.copy_from_slice(&sig_xmss[PARAMS.wots_sig() + k*PARAMS.spx_n .. PARAMS.wots_sig() + (k+1)*PARAMS.spx_n]);
            buf1.copy_from_slice(&node0);

        }

        // compute the parent node
        node1 = h(&pk_seed, &adrs, &buf0, &buf1);
        
        // save the parent node's value to become the next iteration's child node
        node0.copy_from_slice(&node1);

    }

    let pk_xmss: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    pk_xmss
}

