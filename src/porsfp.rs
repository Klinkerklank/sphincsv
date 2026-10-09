
// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * PORS+FP algorithms, based on:
 * [AK25] Abri, M. and Katz, J., 'Shorter Hash-Based Signatures Using Forced Pruning', Aug 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-05 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::params::PARAMS;  // the SPHINCS+V parameters
use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants
use crate::tweakable_hashes::{prf, f, h, h2}; // hash function instantiations

use std::vec::Vec; // for using lists of coordinate pairs

/////////////////////// HELPER FUNCTIONS ///////////////////////

// compute the parent's coordinates from a given node's (i,z) coordinates
fn parent(
    // i = horizontal index of the node in the PORS+FP tree
    // z = height of the node in the PORS+FP tree
    (i, z): (u32, u32), // node
) -> (u32, u32) {
    assert!(z < PARAMS.spx_h_bar() as u32, "\x1b[1;91mCannot get parent of the PORS+FP tree root ({}, {})\x1b[0m", i, z);

    (i>>1, z+1)
}

// compute the left child's coordinates from a given node's (i,z) coordinates
fn lchild(
    // i = horizontal index of the node in the PORS+FP tree
    // z = height of the node in the PORS+FP tree
    (i, z): (u32, u32), // node
) -> (u32, u32) {
    assert!(z > 0, "\x1b[1;91mCannot get left child of node ({}, {}) with z=0\x1b[0m", i, z);

    (i<<1, z-1)
}

// compute the right child's coordinates from a given node's (i,z) coordinates
fn rchild(
    // i = horizontal index of the node in the PORS+FP tree
    // z = height of the node in the PORS+FP tree
    (i, z): (u32, u32), // node
) -> (u32, u32) {
    assert!(z > 0, "\x1b[1;91mCannot get right child of a node with z=0\x1b[0m");

    ((i<<1)+1, z-1)
}

// compute the sibling's coordinates from a given node's (i,z) coordinates
fn sibling(
    // i = horizontal index of the node in the PORS+FP tree
    // z = height of the node in the PORS+FP tree
    (i, z): (u32, u32), // node
) -> (u32, u32) {
    (i^1, z)
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

// check whether a given leaf index is valid in the lowest layer of the force-pruned PORS tree
fn is_valid_leaf(
    index: u32
) -> bool {
    index <= ((2*PARAMS.spx_t - (1<<PARAMS.spx_h_bar()) - 1) as u32)
}

// make a given invalid lowest-layer leaf index (in the force-pruned PORS tree) valid,
// by finding what its horizontal index on the second layer should be
fn make_valid_leaf(
    index: u32
) -> u32 { // -> valid horizontal index
    let last_leaf_idx: u32 = (2*PARAMS.spx_t - (1<<PARAMS.spx_h_bar()) - 1) as u32;

    (last_leaf_idx + 2*(index - last_leaf_idx)) >> 1
}

// turn a set of indices in the range 0..(t choose k) into the sets I and P for the Octopus algorithm,
// which is to say initialise I to the list of leaf nodes that are on the lowest tree layer,
// and initialise P to the list of leaf nodes that are one layer above
fn init_octopus(
    indices: Vec<u32>, // set of k unique indices = 0..(t choose k)
) -> (Vec<(u32, u32)>, Vec<(u32, u32)>) { // -> leaf_nodes, prnt_nodes

    let mut leaf_nodes: Vec<(u32, u32)> = vec![]; // the list of leaf nodes for Octopus (I)
    let mut prnt_nodes: Vec<(u32, u32)> = vec![]; // the list of parent nodes for Octopus (P)

    assert!(indices.len() == PARAMS.spx_k, "\x1b[1;91mindices not of length SPX_K\x1b[0m");

    // process every leaf index
    for index in indices {

        // check whether the leaf index is a valid leaf in the force-pruned PORS tree 
        if is_valid_leaf(index) {

            // index forms a valid leaf index on the lowest (0) layer
            leaf_nodes.push((index, 0u32));

        } else {

            // index needs to be translated to a second-layer (1) leaf
            prnt_nodes.push((make_valid_leaf(index), 1u32));

        }

    }

    assert!(leaf_nodes.len() + prnt_nodes.len() == PARAMS.spx_k, "\x1b[1;91mleaf_nodes + prnt_nodes not of length SPX_K\x1b[0m");

    (leaf_nodes, prnt_nodes)
}

// compute for the given lists of leaves (I) and parent nodes (P), the list of authentication nodes (A),
// i.e. compute A = octopus(I, P) according to the description in [AK25]
fn octopus (
    leaf_nodes: &[(u32, u32)], // the list of leaf nodes for Octopus (I)
    prnt_nodes: &[(u32, u32)], // the list of parent nodes for Octopus (P)
) -> Vec<(u32, u32)> { // -> the list of authentication nodes from Octopus (A)
    
    let mut leaf_nodes: Vec<(u32, u32)> = leaf_nodes.to_vec(); // duplicate (the reference to) I
    let mut prnt_nodes: Vec<(u32, u32)> = prnt_nodes.to_vec(); // duplicate (the reference to) P
    let mut auth_nodes: Vec<(u32, u32)> = vec![]; // the list of authentication nodes from Octopus

    // iterate over the layers bottom-up (root layer is layer 0)
    for _ in 0..PARAMS.spx_h_bar()-1 {

        for &node in &leaf_nodes { // iterate over a reference to I

            // collect in P the parents of the nodes
            prnt_nodes.push(parent(node));

            // collect in A the siblings of the nodes, if the siblings are not in I
            let sibling: (u32, u32) = sibling(node);
            if !leaf_nodes.contains(&sibling) {
                auth_nodes.push(sibling);
            }

        }

        // for the next iteration, set I to P, and reset P to the empty set
        leaf_nodes = prnt_nodes;
        prnt_nodes = vec![];
    }

    auth_nodes
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 14 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 1 FROM [AK25].                                     |
| Generates a PORS+FP private-key value.                       |
+-------------------------------------------------------------*/
pub fn porsfp_skgen(
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut adrs: Adrs,               // ADRS
    i: u32,                       // node's horizontal index
    z: u32,                       // node's height
) -> [u8; PARAMS.spx_n] { // PORS+FP secret key value

    adrs.set_tree_index(i); // set the tree index
    adrs.set_tree_height(z); // set the tree height

    // compute PRF(PK.seed, SK.seed, ADRS)
    let sk: [u8; PARAMS.spx_n] = prf(&pk_seed, &sk_seed, &adrs);

    sk
}

/*-------------------------------------------------------------+
| ALGORITHM 15 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 2 FROM [AK25].                                     |
| Generates a PORS+FP private-key value.                       |
+-------------------------------------------------------------*/
pub fn porsfp_node(
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    i_target: u32,                // node's horizontal index
    z_target: u32,                // node's height
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut adrs: Adrs,               // ADRS
) -> [u8; PARAMS.spx_n] { // PORS+FP secret key value

    // flattened PORS+FP tree
    let mut flat_tree: [u8; PARAMS.pors_tree_size() * PARAMS.spx_n] = [0u8; PARAMS.pors_tree_size() * PARAMS.spx_n];

    for z in 0..z_target+1 {

        let i_start: u32 =  i_target      * (1 << (z_target-z)); //  i_target      * 2^(z_target-z)
        let i_end: u32   = (i_target + 1) * (1 << (z_target-z)); // (i_target + 1) * 2^(z_target-z)

        for i in i_start..i_end {

            // check whether (i, z) is a PORS+FP leaf
            let mut leaf: bool = false;
            if (z == 0) && (is_valid_leaf(i)) {
                leaf = true; // first-layer leaf
            } else if z == 1 && !is_valid_leaf(lchild((i,z)).0) {
                // second-layer leaf (as its left child is not a valid first-layer leaf)
                leaf = true;
            }

            if leaf { // node is a PORS+FP leaf

                // do the ADRS setup for a PORS+FP leaf
                let kpa: u32 = adrs.get_key_pair_addr(); // save the key pair address of this PORS+FP instance
                adrs.set_type_and_clear(adrs_type::PORS_PRF); // set the correct type for computing PORS+FP secret keys
                adrs.set_key_pair_addr(kpa); // set the stored key pair address

                // compute the secret key
                let sk: [u8; PARAMS.spx_n] = porsfp_skgen(sk_seed, pk_seed, adrs, i, z);

                // compute the hash of the secret key
                let node: [u8; PARAMS.spx_n] = f(pk_seed, &adrs, &sk);

                // compute the byte offset of node (i, z) in the flattened tree
                let idx: usize = flat_tree_idx((i, z)) * PARAMS.spx_n;

                // set the hashed secret key in the flattened tree
                flat_tree[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

            } else if z >= 1 { // node is an internal PORS+FP node

                // get the left child
                let idx: usize = flat_tree_idx(lchild((i, z))) * PARAMS.spx_n;
                let mut lnode: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
                lnode.copy_from_slice(&flat_tree[idx..idx+PARAMS.spx_n]);

                // get the right child
                let idx: usize = flat_tree_idx(rchild((i, z))) * PARAMS.spx_n;
                let mut rnode: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
                rnode.copy_from_slice(&flat_tree[idx..idx+PARAMS.spx_n]);

                // compute the relevant ADRS
                let kpa: u32 = adrs.get_key_pair_addr(); // save the key pair address of this PORS+FP instance
                adrs.set_type_and_clear(adrs_type::PORS_TREE); // set the correct type for computing PORS+FP internal nodes
                adrs.set_key_pair_addr(kpa); // set the stored key pair address
                adrs.set_tree_index(i); // set the tree index
                adrs.set_tree_height(z); // set the tree height

                // compute node = H(PK.seed, ADRS, lnode, rnode)
                let node: [u8; PARAMS.spx_n] = h(pk_seed, &adrs, &lnode, &rnode);

                // compute the byte offset of node (i, z) in the flattened tree
                let idx: usize = flat_tree_idx((i, z)) * PARAMS.spx_n;

                // set the internal node in the flattened tree
                flat_tree[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

            }

            // else (i,z) is an invalid PORS+FP node (i.e. a pruned leaf),
            // in which case we do not compute anything

        }

    }

    // get the root of the subtree at (i_target, z_target)
    let idx: usize = flat_tree_idx((i_target, z_target)) * PARAMS.spx_n; // compute the byte offset of node (i_target, z_target) in the flattened tree
    let mut node: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n]; // declare the subtree root value array
    node.copy_from_slice(&flat_tree[idx..idx+PARAMS.spx_n]); // copy the subtree root from the flattened tree

    node
}

/*-------------------------------------------------------------+
| ALGORITHM 16 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 2 FROM [AK25].                                     |
| Generates a PORS+FP signature.                               |
+-------------------------------------------------------------*/
pub fn porsfp_sign(
    md: &[u8; PARAMS.spx_n],      // message digest
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &mut Adrs,              // ADRS
) -> [u8; PARAMS.porsfp_sig()] { // PORS+FP signature

    let mut ctr: u32 = 0; // incrementing counter for leaf-set computing

    let mut leaf_nodes: Vec<(u32, u32)> = vec![]; // the list of leaf nodes (I) for Octopus
    let mut prnt_nodes: Vec<(u32, u32)> = vec![]; // the list of parent nodes (P) for Octopus
    let mut auth_nodes: Vec<(u32, u32)> = vec![]; // the list of authentication nodes (A) from Octopus

    loop {

        // indices = (H_2(md || ctr))
        let indices: Vec<u32> = h2(pk_seed, adrs, md, ctr);

        // convert indices to the two lists I and P
        (leaf_nodes, prnt_nodes) = init_octopus(indices);

        // A = octopus(I, P)
        auth_nodes = octopus(&leaf_nodes, &prnt_nodes);

        // check whether the size of A is small enough 
        if auth_nodes.len() <= PARAMS.spx_mmax {
            break; // counter value found that gives a small enough set of authentication nodes
        }

        ctr += 1; // advance to the next counter value to try

    }

    println!("counter found! ctr={}", ctr);

    // sig_porsfp = (ctr, {F_SK(i)}_i∈I, {y_i}_i∈A), initialised to all-zero
    let mut sig_porsfp: [u8; PARAMS.porsfp_sig()] = [0u8; PARAMS.porsfp_sig()];

    // set the counter
    sig_porsfp[0..4].copy_from_slice(&ctr.to_be_bytes());

    let mut idx: usize = 4; // byte index in sig_porsfp

    // do the ADRS setup for the PORS+FP leaves (which is the same for every leaf)
    let kpa: u32 = adrs.get_key_pair_addr(); // save the key pair address of this PORS+FP instance
    adrs.set_type_and_clear(adrs_type::PORS_PRF); // set the correct type for computing PORS+FP secret keys
    adrs.set_key_pair_addr(kpa); // set the stored key pair address

    // store the PORS+FP leaves, one at a time
    for (i, z) in leaf_nodes {

        // compute the secret key
        let sk: [u8; PARAMS.spx_n] = porsfp_skgen(sk_seed, pk_seed, *adrs, i, z);

        // compute the hash of the secret key
        let node: [u8; PARAMS.spx_n] = f(pk_seed, adrs, &sk);

        // set the hashed secret key in the signature
        sig_porsfp[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

        idx += PARAMS.spx_n; // one leaf has been set

    }

    // compute {y_i}_i∈A using {F_SK (i)}_i∈[t]
    // set the authentication nodes, one at a time
    for (i, z) in auth_nodes {

        // compute the PORS+FP authentication node at position (i, z) within the tree
        let node: [u8; PARAMS.spx_n] = porsfp_node(sk_seed, i, z, pk_seed, *adrs);

        // set the authentication node value in the signature
        sig_porsfp[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

        idx += PARAMS.spx_n; // one authentication node has been set

    }

    // set any unneeded authentication node spots to all-zero
    while idx < PARAMS.porsfp_sig() {
        let node: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
        sig_porsfp[idx..idx+PARAMS.spx_n].copy_from_slice(&node);
        idx += PARAMS.spx_n;
    }

    sig_porsfp
}

/*-------------------------------------------------------------+
| ALGORITHM 17 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 3 FROM [AK25].                                     |
| Computes a PORS+FP root from a signature.                    |
+-------------------------------------------------------------*/
pub fn porsfp_pkfromsig(
    sig_porsfp: [u8; PARAMS.porsfp_sig()], // PORS+FP signature
    md: &[u8; PARAMS.spx_n],               // message digest
    pk_seed: &[u8; PARAMS.spx_n],          // PK.seed
    adrs: &mut Adrs,                       // ADRS
) -> [u8; PARAMS.spx_n] { // PORS+FP signature

    // extract the counter value from the signature
    let ctr_bytes: [u8; 4] = sig_porsfp[0..4].try_into().unwrap();
    let ctr: u32 = u32::from_be_bytes(ctr_bytes);

    let mut leaf_nodes: Vec<(u32, u32)> = vec![]; // the list of leaf nodes (I) for Octopus
    let mut prnt_nodes: Vec<(u32, u32)> = vec![]; // the list of parent nodes (P) for Octopus
    let mut auth_nodes: Vec<(u32, u32)> = vec![]; // the list of authentication nodes (A) from Octopus

    // indices = (H_2(md || ctr))
    let indices: Vec<u32> = h2(pk_seed, adrs, md, ctr);

    // convert indices to the two lists I and P
    (leaf_nodes, prnt_nodes) = init_octopus(indices);

    // A = octopus(I, P)
    auth_nodes = octopus(&leaf_nodes, &prnt_nodes);

    assert!(auth_nodes.len() <= PARAMS.spx_mmax, "\x1b[1;91mauth_nodes not of length SPX_MMAX\x1b[0m");

    // flattened PORS+FP tree
    let mut flat_tree: [u8; PARAMS.pors_tree_size() * PARAMS.spx_n] = [0u8; PARAMS.pors_tree_size() * PARAMS.spx_n];
    let mut populated: [bool; PARAMS.pors_tree_size()] = [false; PARAMS.pors_tree_size()];

    // extract the first-layer leaves, second-layer leaves, and authentication nodes from the signature
    let mut idx_sig: usize = 4; // byte index in sig_porsfp
    for (i, z) in leaf_nodes.iter() {

        // compute the byte offset of node (i, z) in the flattened tree
        let idx: usize = flat_tree_idx((*i, *z));
        let idx_flat: usize = idx * PARAMS.spx_n;

        // set the node in the flattened tree, and set its node position to populated
        flat_tree[idx_flat..idx_flat+PARAMS.spx_n].copy_from_slice(&sig_porsfp[idx_sig..idx_sig+PARAMS.spx_n]);
        populated[idx] = true;

        idx_sig += PARAMS.spx_n; // one node has been set

    }
    for (i, z) in prnt_nodes.iter() {

        // compute the byte offset of node (i, z) in the flattened tree
        let idx: usize = flat_tree_idx((*i, *z));
        let idx_flat: usize = idx * PARAMS.spx_n;

        // set the node in the flattened tree, and set its node position to populated
        flat_tree[idx_flat..idx_flat+PARAMS.spx_n].copy_from_slice(&sig_porsfp[idx_sig..idx_sig+PARAMS.spx_n]);
        populated[idx] = true;

        idx_sig += PARAMS.spx_n; // one node has been set

    }
    for (i, z) in auth_nodes.iter() {

        // compute the byte offset of node (i, z) in the flattened tree
        let idx: usize = flat_tree_idx((*i, *z));
        let idx_flat: usize = idx * PARAMS.spx_n;

        // set the node in the flattened tree, and set its node position to populated
        flat_tree[idx_flat..idx_flat+PARAMS.spx_n].copy_from_slice(&sig_porsfp[idx_sig..idx_sig+PARAMS.spx_n]);
        populated[idx] = true;

        idx_sig += PARAMS.spx_n; // one node has been set

    }

    // compute the PORS+FP tree root from the partially-filled tree
    // (which now contains all signature leaves and authentication nodes)

    for z in 0..PARAMS.spx_h_bar() { // vertically iterate over the layers

        for i in 0..(1 << (PARAMS.spx_h_bar()-z)) { // horizontally iterate over all nodes in the current layer

            // compute the index of node (i, z) in the flattened tree
            let idx: usize = flat_tree_idx((i, z as u32));

            // if (i, z) is populated, compute its parent
            if populated[idx] {

                // get the left child (which is the node (i, z))
                let idx_offset: usize = idx * PARAMS.spx_n;
                let mut lnode: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
                lnode.copy_from_slice(&flat_tree[idx_offset..idx_offset+PARAMS.spx_n]);

                // get the right child
                let idx_offset: usize = flat_tree_idx(sibling((i, z as u32))) * PARAMS.spx_n;
                let mut rnode: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
                rnode.copy_from_slice(&flat_tree[idx_offset..idx_offset+PARAMS.spx_n]);

                // get the parent's coordinates
                let (i_parent, z_parent): (u32, u32) = parent((i, z as u32));

                // compute the relevant ADRS
                let kpa: u32 = adrs.get_key_pair_addr(); // save the key pair address of this PORS+FP instance
                adrs.set_type_and_clear(adrs_type::PORS_TREE); // set the correct type for computing PORS+FP internal nodes
                adrs.set_key_pair_addr(kpa); // set the stored key pair address
                adrs.set_tree_index(i_parent); // set the tree index
                adrs.set_tree_height(z_parent); // set the tree height

                // compute node = H(PK.seed, ADRS, lnode, rnode)
                let node: [u8; PARAMS.spx_n] = h(pk_seed, &adrs, &lnode, &rnode);

                // compute the byte offset of node (i, z) in the flattened tree
                let idx_parent: usize = flat_tree_idx((i_parent, z_parent));
                let idx_offset: usize = idx_parent * PARAMS.spx_n;

                // set the internal node in the flattened tree
                flat_tree[idx_offset..idx_offset+PARAMS.spx_n].copy_from_slice(&node);

                // set the parent node to populated
                populated[idx_parent] = true;

            }

        }

    }

    // get the root of the subtree at (i_target, z_target)
    let idx_flat: usize = flat_tree_idx((0u32, PARAMS.spx_h_bar() as u32)) * PARAMS.spx_n; // compute the byte offset of the root of the flattened tree
    let mut root: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n]; // declare the root value array
    root.copy_from_slice(&flat_tree[idx_flat..idx_flat+PARAMS.spx_n]); // copy the root from the flattened tree

    root
}