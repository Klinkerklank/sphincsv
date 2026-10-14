/*
 * XMSS algorithms
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::params::{N, H_PRIME, H_BAR, XMSS_TREE_SIZE, WOTS_SIG, XMSS_SIG}; // parameter values

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
    ((1 << (H_BAR + 1)) - (1 << (H_BAR + 1 - (z as usize))) + i) as usize
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 9 FROM SLH-DSS (FIPS 205)                          |
| Computes the root of a Merkle subtree of WOTS+ public keys.  |
| (iterative instead of recursive)                             |
+-------------------------------------------------------------*/
pub fn xmss_node(
    sk_seed: &[u8; N], // SK.seed
    i_target: u32,     // target node index (horizontal)
    z_target: u32,     // target node height
    pk_seed: &[u8; N], // PK.seed
    mut adrs: Adrs,    // ADRS
) -> [u8; N] // -> root
{

    // array buffer with enough place to fit the entire (flattened) XMSS tree
    // note that for efficiency only those nodes are computed that are needed
    // to find the target node, so not necessarily the entire buffer is filled
    // TODO replace this naive approach with something like TreeHash
    let mut flat_tree: [u8; XMSS_TREE_SIZE * N] = [0u8; XMSS_TREE_SIZE * N];

    // iterate over the layers, bottom to top
    for z in 0..(z_target as usize)+1 {

        let i_start: usize =  (i_target as usize)      * (1 << ((z_target as usize)-z)); //  i_target      * 2^(z_target-z)
        let i_end: usize   = ((i_target as usize) + 1) * (1 << ((z_target as usize)-z)); // (i_target + 1) * 2^(z_target-z)

        // iterate over the nodes in a layer, left to right
        for i in i_start..i_end {

            if z == 0 { // layer-0 leaf node: the node value is a WOTS+ public key

                // set the correct values in ADRS for WOTS hashing
                adrs.set_type_and_clear(adrs_type::WOTS_HASH);
                adrs.set_key_pair_addr(i as u32);
                
                // compute the WOTS+ public key
                flat_tree[i*N..(i+1)*N].copy_from_slice(&wots_pkgen(&sk_seed, &pk_seed, adrs));

            } else { // internal node: the node value is the hash of its two children lnode and rnode

                // get the left child
                let mut idx: usize = flat_tree_idx(lchild((i as u32, z as u32))) * N;
                let mut lnode: [u8; N] = [0u8; N];
                lnode.copy_from_slice(&flat_tree[idx..idx+N]);

                // get the right child
                idx += N;
                let mut rnode: [u8; N] = [0u8; N];
                rnode.copy_from_slice(&flat_tree[idx..idx+N]);

                // compute the relevant ADRS
                adrs.set_type_and_clear(adrs_type::TREE); // set the correct type for computing XMSS internal nodes
                adrs.set_tree_index(i as u32); // set the tree index
                adrs.set_tree_height(z as u32); // set the tree height

                // compute node = H(PK.seed, ADRS, lnode, rnode)
                let node: [u8; N] = h(pk_seed, &adrs, &lnode, &rnode);

                // compute the byte offset of node (i, z) in the flattened tree
                let idx: usize = flat_tree_idx((i as u32, z as u32)) * N;

                // set the internal node in the flattened tree
                flat_tree[idx..idx+N].copy_from_slice(&node);

            }

        }

    }

    // get the root of the subtree at (i_target, z_target)
    let idx: usize = flat_tree_idx((i_target, z_target)) * N; // compute the byte offset of node (i_target, z_target) in the flattened tree
    let mut node: [u8; N] = [0u8; N]; // declare the subtree root value array
    node.copy_from_slice(&flat_tree[idx..idx+N]); // copy the subtree root from the flattened tree

    node
}

/*-------------------------------------------------------------+
| ALGORITHM 10 FROM SLH-DSS (FIPS 205)                         |
| Generates an XMSS signature.                                 |
+-------------------------------------------------------------*/
pub fn xmss_sign(
    m: &[u8; N],       // message to sign (XMSS public key or PORS+FP public key)
    sk_seed: &[u8; N], // SK.seed
    idx: u32,          // WOTS+ leaf index to sign with
    pk_seed: &[u8; N], // PK.seed
    mut adrs: Adrs,    // ADRS
) -> [u8; XMSS_SIG] // -> sig_xmss
{

    // initialise the XMSS signature
    let mut sig_xmss: [u8; XMSS_SIG] = [0u8; XMSS_SIG];

    // compute the sibling node's horizontal index
    let mut k: u32 = idx ^ 1;

    // compute and store the authentication path AUTH
    for z in 0..H_PRIME {
        
        // compute the sibling node
        let auth_node: [u8; N] = xmss_node(&sk_seed, k, z as u32, &pk_seed, adrs);

        // store the sibling node in the XMSS signature
        sig_xmss[WOTS_SIG+z*N .. WOTS_SIG+(z+1)*N].copy_from_slice(&auth_node);
        
        // update the sibling node's horizontal index for the next iteration
        k = (k >> 1) ^ 1;

    }

    // set the correct values in ADRS for WOTS+ hashing
    adrs.set_type_and_clear(adrs_type::WOTS_HASH);
    adrs.set_key_pair_addr(idx);
    
    // compute the WOTS+ signature on the XMSS or PORS+FP public key
    let sig_wots: [u8; WOTS_SIG] = wots_sign(&m, &sk_seed, &pk_seed, adrs);

    // store the WOTS+ signature in the XMSS signature
    sig_xmss[0..WOTS_SIG].copy_from_slice(&sig_wots);

    sig_xmss
}

/*-------------------------------------------------------------+
| ALGORITHM 11 FROM SLH-DSS (FIPS 205)                         |
| Computes an XMSS public key from an XMSS signature.          |
+-------------------------------------------------------------*/
pub fn xmss_pkfromsig(
    idx: u32,                  // WOTS+ leaf index to sign with
    sig_xmss: &[u8; XMSS_SIG], // XMSS signature
    m: &[u8; N],               // message to sign (XMSS public key or PORS+FP public key)
    pk_seed: &[u8; N],         // PK.seed
    mut adrs: Adrs,            // ADRS
) -> [u8; N] // -> pk_xmss
{

    // set the correct values in ADRS for WOTS+ hashing
    adrs.set_type_and_clear(adrs_type::WOTS_HASH);
    adrs.set_key_pair_addr(idx);

    // separate the WOTS+ signature from the XMSS signature
    let mut sig_wots: [u8; WOTS_SIG] = [0u8; WOTS_SIG];
    sig_wots.copy_from_slice(&sig_xmss[0..WOTS_SIG]);

    // initialise the node buffers used in the loop
    let mut node0: [u8; N];
    let mut node1: [u8; N];
    let mut buf0: [u8; N] = [0u8; N];
    let mut buf1: [u8; N] = [0u8; N];
    
    // compute the WOTS+ public key from the WOTS+ signature
    node0 = wots_pkfromsig(&sig_wots, &m, &pk_seed, adrs);

    // set the correct values in ADRS for Merkle tree hashing
    adrs.set_type_and_clear(adrs_type::TREE);
    adrs.set_tree_index(idx);

    for k in 0..H_PRIME {

        // set the parent node's height
        adrs.set_tree_height(k as u32 + 1);

        if (idx/(1<<k)) % 2 == 0 { // floor(idx / 2^k) is even
            
            // compute the parent node's horizontal index
            let idx_tree: u32 = adrs.get_tree_index() >> 1;
            
            // set the parent node's tree index
            adrs.set_tree_index(idx_tree);

            // buf = buf0 || buf1 = node0 || AUTH[k]
            buf0.copy_from_slice(&node0);
            buf1.copy_from_slice(&sig_xmss[WOTS_SIG + k*N .. WOTS_SIG + (k+1)*N]);

        } else { // floor(idx / 2^k) is odd
            
            // compute the parent node's horizontal index
            let idx_tree: u32 = (adrs.get_tree_index()-1) >> 1;
            
            // set the parent node's tree index
            adrs.set_tree_index(idx_tree);

            // buf = buf0 || buf1 = AUTH[k] || node0
            buf0.copy_from_slice(&sig_xmss[WOTS_SIG + k*N .. WOTS_SIG + (k+1)*N]);
            buf1.copy_from_slice(&node0);

        }

        // compute the parent node
        node1 = h(&pk_seed, &adrs, &buf0, &buf1);
        
        // save the parent node's value to become the next iteration's child node
        node0.copy_from_slice(&node1);

    }

    let pk_xmss: [u8; N] = [0u8; N];

    pk_xmss
}
