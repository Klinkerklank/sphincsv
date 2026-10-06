
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
use crate::tweakable_hashes::{prf, f, h2}; // hash function instantiations

use std::vec::Vec; // for using lists of coordinate pairs

/////////////////////// HELPER FUNCTIONS ///////////////////////

// compute the parent's coordinates from a given node's (i,z) coordinates
fn parent(
    i: u32, // horizontal index of the node in the PORS+FP tree
    z: u32, // height of the node in the PORS+FP tree
) -> (u32, u32) {
    (i>>1, z+1)
}

// compute the left child's coordinates from a given node's (i,z) coordinates
fn lchild(
    i: u32, // horizontal index of the node in the PORS+FP tree
    z: u32, // height of the node in the PORS+FP tree
) -> (u32, u32) {
    (2*i, z-1)
}

// compute the right child's coordinates from a given node's (i,z) coordinates
fn rchild(
    i: u32, // horizontal index of the node in the PORS+FP tree
    z: u32, // height of the node in the PORS+FP tree
) -> (u32, u32) {
    (2*i+1, z-1)
}

// compute the sibling's coordinates from a given node's (i,z) coordinates
fn sibling(
    i: u32, // horizontal index of the node in the PORS+FP tree
    z: u32, // height of the node in the PORS+FP tree
) -> (u32, u32) {
    (i^1, z)
}

// check whether a given leaf index is valid in the force-pruned PORS tree
fn is_valid_leaf(
    index: u32
) -> bool {
    index <= ((2*PARAMS.spx_t - (1<<PARAMS.spx_h_bar()) - 1) as u32)
}

// make a given invalid leaf index (in the force-pruned PORS tree) valid,
// by finding what its horizontal index on the second layer should be
fn make_valid_leaf(
    index: u32
) -> u32 { // -> valid horizontal index
    // (last_leaf_idx + 2*(index - last_leaf_idx)) / 2
    (((2*PARAMS.spx_t - (1<<PARAMS.spx_h_bar()) - 1) as u32) + 2*(index - ((2*PARAMS.spx_t - (1<<PARAMS.spx_h_bar()) - 1) as u32))) >> 1
}

// turn a set of indices in the range 0..(t choose k) into the sets I and P for the Octopus algorithm,
// which is to say initialise I to the list of leaf nodes that are on the lowest tree layer,
// and initialise P to the list of leaf nodes that are one layer above
fn init_octopus(
    indices: Vec<u32>, // set of k unique indices = 0..(t choose k)
) -> (Vec<(u32, u32)>, Vec<(u32, u32)>) { // -> leaf_nodes, prnt_nodes

    let mut leaf_nodes: Vec<(u32, u32)> = vec![]; // the list of leaf nodes for Octopus (I)
    let mut prnt_nodes: Vec<(u32, u32)> = vec![]; // the list of parent nodes for Octopus (P)

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

    (leaf_nodes, prnt_nodes)
}

// compute for the given lists of leaves (I) and parent nodes (P), the list of authentication nodes (A),
// i.e. compute A = octopus(I, P) according to the description in [AK25]
fn octopus (
    leaf_nodes: &Vec<(u32, u32)>, // the list of leaf nodes for Octopus (I)
    prnt_nodes: &Vec<(u32, u32)>, // the list of parent nodes for Octopus (P)
) -> Vec<(u32, u32)> { // -> the list of authentication nodes from Octopus (A)
    
    let mut auth_nodes: Vec<(u32, u32)> = vec![]; // the list of authentication nodes from Octopus

    auth_nodes
}







// // the Octopus algorithm, for efficiently computing what nodes need
// // to be revealed in the authentication path of a PORS+FP signature
// fn octopus(
//     i_input: HashSet<u32>, // the set of leaf-layer authentication nodes
// ) -> HashSet<u32> {

//     let mut i: HashSet<u32> = HashSet::new(); // the set of nodes to authenticate
//     let mut p: HashSet<u32> = HashSet::new(); // the set of parent nodes to authenticate
//     let mut a: HashSet<u32> = HashSet::new(); // the set of authentication nodes
    
//     // 2t represents twice the total number of terminal nodes, while 2^{h_bar} is the 
//     // total number of leaves in the corresponding perfect tree
//     // since every internal node has exactly two children, the difference 2t-2^{h_bar}\) gives the number of nodes on the lowest layer.
//     let leaf_layer_end_idx: u32 = (2*PARAMS.spx_t - (1 << PARAMS.spx_h_bar())) as u32;
    
//     // initialise I and P, which is to say:
//     // I = the authentication nodes that are at the leaf layer (0),
//     // P = the authentication nodes that are one layer above (1)
//     // (because a PORS+FP tree is complete but not necessarily perfect)
//     for node in i_input {

//         if node < leaf_layer_end_idx {
//             i.insert(node);
//         } else {
//             p.insert(node);
//         }

//     }

//     // iterate over the layers bottom-up (root layer is layer 0)
//     for _ in (0..PARAMS.spx_h_prime()-1).rev() {

//         for &node in &i { // iterate over a reference to I

//             // collect in P the parent of the node
//             p.insert(par(node));

//             // collect in A the sibling of the node, if the sibling is not in I
//             let sibling: u32 = sib(node);
//             if !i.contains(&sibling) {
//                 a.insert(sibling);
//             }

//         }

//         // for the next iteration, set I to P, and reset P to the empty set
//         i = p;
//         p = HashSet::new();
//     }

//     a

// }

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 14 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 1 FROM [AK25].                                     |
| Generates a PORS+FP private-key value.                       |
+-------------------------------------------------------------*/
fn porsfp_skgen(
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut adrs: Adrs,               // ADRS
    i: u32,                       // node's horizontal index
    z: u32,                       // node's height
) -> [u8; PARAMS.spx_n] { // PORS+FP secret key value

    // set the tree index
    adrs.set_tree_index(i);

    // set the tree height
    adrs.set_tree_height(z);

    // compute PRF(PK.seed, SK.seed, ADRS)
    let sk = prf(&pk_seed, &sk_seed, &adrs);

    sk
}

/*-------------------------------------------------------------+
| ALGORITHM 15 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 2 FROM [AK25].                                     |
| Generates a PORS+FP private-key value.                       |
+-------------------------------------------------------------*/
fn porsfp_node(
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    i: u32,                       // node's horizontal index
    z: u32,                       // node's height
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut adrs: Adrs,               // ADRS
) -> [u8; PARAMS.spx_n] { // PORS+FP secret key value



    let trunc: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    trunc
}

/*-------------------------------------------------------------+
| ALGORITHM 16 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 2 FROM [AK25].                                     |
| Generates a PORS+FP signature.                               |
+-------------------------------------------------------------*/
fn porsfp_sign(
    md: &[u8; PARAMS.spx_n],      // message digest
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &mut Adrs,              // ADRS
) -> [u8; PARAMS.pors_sig()] { // PORS+FP signature

    let mut ctr: u32 = 0; // incrementing counter for leaf-set computing

    let mut leaf_nodes: Vec<(u32, u32)> = vec![]; // the list of leaf nodes for Octopus
    let mut prnt_nodes: Vec<(u32, u32)> = vec![]; // the list of parent nodes for Octopus
    let mut auth_nodes: Vec<(u32, u32)> = vec![]; // the list of authentication nodes from Octopus

    loop {
        // indices = (H_2(md || ctr))
        let indices: Vec<u32> = h2(pk_seed, adrs, md, ctr);

        // convert indices to the two lists I and P
        (leaf_nodes, prnt_nodes) = init_octopus(indices);

        // A = octopus(I, P)
        auth_nodes = octopus(&leaf_nodes, &prnt_nodes);

        // check whether the size of A is small enough 
        if auth_nodes.len() <= PARAMS.spx_mmax {
            break;
        }

        ctr += 1;
    }

    // sig_pors = (ctr, {F_SK(i)}_i∈I, {y_i}_i∈A), initialised to all-zero
    let mut sig_pors: [u8; PARAMS.pors_sig()] = [0u8; PARAMS.pors_sig()];

    // set the counter
    sig_pors[0..4].copy_from_slice(&ctr.to_be_bytes());

    let mut idx: usize = 4; // byte index in sig_pors

    // do the ADRS setup for the PORS+FP leaves (which is the same for every leaf)
    let kpa: u32 = adrs.get_key_pair_addr();                // save the key pair address of this PORS+FP instance
    adrs.set_type_and_clear(adrs_type::PORS_PRF); // set the correct type for computing PORS+FP secret keys
    adrs.set_key_pair_addr(kpa);                            // set the stored key pair address

    // store the PORS+FP leaves, one at a time
    for (i, z) in leaf_nodes {

        // compute the secret key
        let sk: [u8; PARAMS.spx_n] = porsfp_skgen(sk_seed, pk_seed, *adrs, i, z);

        // compute the hash of the secret key
        let node: [u8; PARAMS.spx_n] = f(pk_seed, adrs, &sk);

        // set the hashed secret key in the signature
        sig_pors[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

        idx += PARAMS.spx_n; // one leaf has been set

    }

    // compute {y_i}_i∈A using {F_SK (i)}_i∈[t]
    // set the authentication nodes, one at a time
    for (i, z) in auth_nodes {

        // compute the PORS+FP authentication node at position (i, z) within the tree
        let node: [u8; PARAMS.spx_n] = porsfp_node(sk_seed, i, z, pk_seed, *adrs);

        // set the authentication node value in the signature
        sig_pors[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

        idx += PARAMS.spx_n; // one authentication node has been set

    }

    sig_pors
}