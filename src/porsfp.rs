
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

/////////////////////// HELPER FUNCTIONS ///////////////////////

// compute the tree index of the parent of a node
fn par(
    node: u32, // node to compute the parent of
) -> u32 {
    node >> 1
}

// compute the tree index of the sibling of a node
fn sib(
    node: u32, // node to compute the sibling of
) -> u32 {
    node ^ 0x1
}

// the Octopus algorithm, for efficiently computing what nodes need
// to be revealed in the authentication path of a PORS+FP signature
fn octopus(
    mut i_input: HashSet<u32>, // the set of leaf-layer authentication nodes
) -> HashSet<u32> {

    let mut i: HashSet<u32> = HashSet::new(); // the set of nodes to authenticate
    let mut p: HashSet<u32> = HashSet::new(); // the set of parent nodes to authenticate
    let mut a: HashSet<u32> = HashSet::new(); // the set of authentication nodes
    
    // 2t represents twice the total number of terminal nodes, while 2^{h_bar} is the 
    // total number of leaves in the corresponding perfect tree
    // since every internal node has exactly two children, the difference 2t-2^{h_bar}\) gives the number of nodes on the lowest layer.
    let leaf_layer_end_idx: u32 = (2*PARAMS.spx_t - (1 << PARAMS.spx_h_bar())) as u32;
    
    // initialise I and P, which is to say:
    // I = the authentication nodes that are at the leaf layer (0),
    // P = the authentication nodes that are one layer above (1)
    // (because a PORS+FP tree is complete but not necessarily perfect)
    for node in i_input {

        if node < leaf_layer_end_idx {
            i.insert(node);
        } else {
            p.insert(node);
        }

    }

    // iterate over the layers bottom-up (root layer is layer 0)
    for _ in (0..PARAMS.spx_h_prime()-1).rev() {

        for &node in &i { // iterate over a reference to I

            // collect in P the parent of the node
            p.insert(par(node));

            // collect in A the sibling of the node, if the sibling is not in I
            let sibling: u32 = sib(node);
            if !i.contains(&sibling) {
                a.insert(sibling);
            }

        }

        // for the next iteration, set I to P, and reset P to the empty set
        i = p;
        p = HashSet::new();
    }

    a

}

//////////////////////// MAIN FUNCTIONS ////////////////////////

use crate::params::PARAMS;          // the SPHINCS+V parameters
use crate::adrs::Adrs;              // ADRS data structure
use crate::adrs::adrs_type;         use crate::tweakable_hashes::f;
// ADRS type constants
use crate::tweakable_hashes::{prf}; // hash function instantiations

use std::collections::HashSet; // set for the octopus algorithm

/*-------------------------------------------------------------+
| ALGORITHM 14 FROM SLH-DSS (FIPS 205) adapted for             |
| ALGORITHM 1 FROM [AK25].                                     |
| Generates a PORS+FP private-key value.                       |
+-------------------------------------------------------------*/
fn porsfp_skgen(
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &Adrs,                  // ADRS
    idx: u32,                     // secret key index
) -> [u8; PARAMS.spx_n] { // PORS+FP secret key value

    let mut skadrs = adrs.clone(); // clone the ADRS structure

    // set the correct type for computing PORS+FP secret keys
    skadrs.set_type_and_clear(adrs_type::PORS_PRF);

    // get the key pair address from ADRS, and set it in skadrs
    let kpa = adrs.get_key_pair_addr();
    skadrs.set_key_pair_addr(kpa);

    // set the tree index
    skadrs.set_tree_index(idx);

    // compute PRF(PK.seed, SK.seed, ADRS)
    let sk = prf(&pk_seed, &sk_seed, &skadrs);

    sk
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

    loop {
        // I = (H_2(md || ctr))
        let i: HashSet<u32> = h2(adrs, md, ctr);

        // A = octopus(I)
        let a: HashSet<u32> = octopus(i);

        // check whether the size of A is small enough 
        if (a.len() <= PARAMS.mmax) {
            break;
        }

        ctr += 1;
    }

    // sig_pors = (ctr, {F_SK(i)}_i∈I, {y_i}_i∈A)
    // initialised to all-zero
    let mut sig_pors: [u8; PARAMS.pors_sig()] = [0u8; PARAMS.pors_sig()];

    // set the counter
    sig_pors[0..4].copy_from_slice(&ctr.to_be_bytes());

    let mut idx: usize = 4; // byte index in sig_pors

    // set the PORS+FP leaves
    for leaf in i {

        // compute the secret key
        let sk: [u8; PARAMS.spx_n] = porsfp_skgen(sk_seed, pk_seed, &adrs, leaf);

        // compute the hash of the secret key
        let node: [u8; PARAMS.spx_n] = f(pk_seed, adrs, &sk);

        // set the hashed secret key in the signature
        sig_pors[idx..idx+PARAMS.spx_n].copy_from_slice(&node);

        idx += PARAMS.spx_n; // one leaf has been set

    }

    // compute {y_i}_i∈A using {F_SK (i)}_i∈[t]
    // set the authentication nodes
    for auth in a {
        let i: u32; // target node index (horizontal)
        let z: u32; // target node height

        let node: [u8; PARAMS.spx_n] = porsfp_node(sk_seed, i, z, pk_seed, adrs);

        idx += PARAMS.spx_n; // one authentication node has been set

    }

    sig_pors
}