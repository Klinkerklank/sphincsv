
// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

// supporting modules
mod params;           // SPHINCS+V parameters
mod adrs;             // ADRS data structure
mod tweakable_hashes; // hash function instantiations

// algorithmic modules
mod porsfp;   // PORS+FP implementation
mod wots;     // WOTS+ implementation
mod xmss;     // XMSS implementation
mod ht;       // HT implementation
mod sphincsv; // SPHINCS+V implementation

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants
use crate::params::PARAMS;  // the SPHINCS+V parameters

use crate::tweakable_hashes::{prf_msg, h_msg}; // hash function instantiations

fn parse_indices(
    _tmp_idx_tree: [u8; PARAMS.spx_idx_tree_len()], // raw tree index data
    _tmp_idx_leaf: [u8; PARAMS.spx_idx_leaf_len()], // raw leaf index data
) -> ([u32; 3], u32) {

    let idx_tree: [u32; 3] = [0u32; 3];
    let idx_leaf: u32 = 0;

    (idx_tree, idx_leaf)
}

fn main() {

    println!();

    let sk_seed: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let sk_prf:  [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let pk_seed: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let pk_root: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let optrand: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    // initialise ADRS
    let mut adrs: Adrs = Adrs::new();

    // compute the root of the PORS+FP instance using porsfp_node
    let pk_node: [u8; PARAMS.spx_n] = porsfp::porsfp_node(&sk_seed, 0 as u32, PARAMS.spx_h_bar() as u32, &pk_seed, adrs);

    println!("root according to porsfp_node:");
    println!("{:02x?}\n", pk_node);

    // construct an abitrary message and context
    let message: [u8; PARAMS.spx_n] = [0xFF; PARAMS.spx_n];
    let context: [u8; PARAMS.spx_n] = [0xAA; PARAMS.spx_n];

    // println!("message:");
    // println!("{:02x?}\n", message);

    // println!("context:");
    // println!("{:02x?}\n", context);

    // compute the message randomiser
    let r: [u8; PARAMS.spx_n] = prf_msg(&sk_prf, &optrand, &context, &message);

    // println!("r:");
    // println!("{:02x?}\n", r);

    // compute the message digest
    let digest: [u8; PARAMS.spx_m()] = h_msg(&r, &pk_seed, &pk_root, &context, &message);

    // println!("digest:");
    // println!("{:02x?}\n", digest);

    // extract md, tmp_idx_tree, and tmp_idx_leaf from digest
    let mut md:           [u8; PARAMS.spx_md_len()]       = [0u8; PARAMS.spx_md_len()];
    let mut tmp_idx_tree: [u8; PARAMS.spx_idx_tree_len()] = [0u8; PARAMS.spx_idx_tree_len()];
    let mut tmp_idx_leaf: [u8; PARAMS.spx_idx_leaf_len()] = [0u8; PARAMS.spx_idx_leaf_len()];
    md          .copy_from_slice(&digest[0                                             .. PARAMS.spx_md_len()                                                    ]);
    tmp_idx_tree.copy_from_slice(&digest[PARAMS.spx_md_len()                           .. PARAMS.spx_md_len()+PARAMS.spx_idx_tree_len()                          ]);
    tmp_idx_leaf.copy_from_slice(&digest[PARAMS.spx_md_len()+PARAMS.spx_idx_tree_len() .. PARAMS.spx_md_len()+PARAMS.spx_idx_tree_len()+PARAMS.spx_idx_leaf_len()]);

    // compute idx_tree and idx_leaf from tmp_idx_tree and tmp_idx_leaf
    let (idx_tree, idx_leaf) = parse_indices(tmp_idx_tree, tmp_idx_leaf);

    // set the ADRS values for the PORS+FP signature generation
    adrs.set_tree_addr(idx_tree);
    adrs.set_type_and_clear(adrs_type::PORS_TREE);
    adrs.set_key_pair_addr(idx_leaf);

    // compute a signature on the message digest md using porsfp_sign
    let sig_porsfp: [u8; PARAMS.porsfp_sig()] = porsfp::porsfp_sign(&md, &sk_seed, &pk_seed, &mut adrs);

    println!("signature computed\n");

    // set the ADRS values for the PORS+FP signature generation
    adrs.set_tree_addr(idx_tree);
    adrs.set_type_and_clear(adrs_type::PORS_TREE);
    adrs.set_key_pair_addr(idx_leaf);

    // compute the root of the PORS+FP instance from the signature using porsfp_pkfromsig
    let pk_sign: [u8; PARAMS.spx_n] = porsfp::porsfp_pkfromsig(&sig_porsfp, &md, &pk_seed, &mut adrs);

    println!("root according to porsfp_pkfromsig:");
    println!("{:02x?}\n", pk_sign);

}

