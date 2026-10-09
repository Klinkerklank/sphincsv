// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * SPHINCS+V top-level functions
 * 
 * author: Dennis op 't Roodt 2026-10-09 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants
use crate::params::PARAMS;  // the SPHINCS+V parameters

use crate::tweakable_hashes::{prf_msg, h_msg}; // hash function instantiations

use crate::porsfp::{porsfp_sign, porsfp_pkfromsig}; // PORS+FP implementation

use rand::RngExt; // for getting random keying material

/////////////////////// HELPER FUNCTIONS ///////////////////////

fn parse_indices(
    _tmp_idx_tree: [u8; PARAMS.spx_idx_tree_len()], // raw tree index data
    _tmp_idx_leaf: [u8; PARAMS.spx_idx_leaf_len()], // raw leaf index data
) -> ([u32; 3], u32) {

    // TODO
    let idx_tree: [u32; 3] = [0u32; 3];
    let idx_leaf: u32 = 0;

    (idx_tree, idx_leaf)
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 18 FROM SLH-DSS (FIPS 205)                         |
| Generates a SPHINCS+V key pair.                              |
+-------------------------------------------------------------*/
fn sphincsv_keygen_internal(
    keyrnd: &[u8; 3*PARAMS.spx_n], // key randomness
) -> ([u8; PARAMS.spx_skbytes()], [u8; PARAMS.spx_pkbytes()]) {

    let mut sk: [u8; PARAMS.spx_skbytes()] = [0u8; PARAMS.spx_skbytes()]; // secret key = [SK.seed, SK.prf, PK.seed, PK.root]
    let mut pk: [u8; PARAMS.spx_pkbytes()] = [0u8; PARAMS.spx_pkbytes()]; // public key =                  [PK.seed, PK.root]

    // copy SK.seed, SK.prf, and PK.seed from the given key randomness to SK
    sk[0..3*PARAMS.spx_n].copy_from_slice(&keyrnd[0..3*PARAMS.spx_n]);

    // copy PK.seed from the given key randomness to PK
    pk[0..PARAMS.spx_n].copy_from_slice(&keyrnd[2*PARAMS.spx_n..3*PARAMS.spx_n]);

    // initialise ADRS
    let mut adrs: Adrs = Adrs::new();

    // set the layer address to the highest hypertree layer
    adrs.set_layer_addr(PARAMS.spx_d as u32);

    // TODO
    // compute PK.root, which is the node in the top-most XMSS tree at
    // horizontal index i = 0 and height z = SPX_H_PRIME

    (sk, pk)
}

/*-------------------------------------------------------------+
| ALGORITHM 21 FROM SLH-DSS (FIPS 205)                         |
| Generates a SPHINCS+V key pair.                              |
| Generates the randomness for sphincsv_keygen_internal.       |
+-------------------------------------------------------------*/
pub fn sphincsv_keygen() -> ([u8; PARAMS.spx_skbytes()], [u8; PARAMS.spx_pkbytes()]) {

    // get a random number generator
    let mut rng: rand::prelude::ThreadRng = rand::rng();

    // generate the additional randomness
    let keyrnd: [u8; 3*PARAMS.spx_n] = rng.random();

    // generate a SPHINCS+V key pair
    let (sk, pk) = sphincsv_keygen_internal(&keyrnd);

    (sk, pk)
}

/*-------------------------------------------------------------+
| ALGORITHM 19 FROM SLH-DSS (FIPS 205)                         |
| Generates a SPHINCS+V signature.                             |
+-------------------------------------------------------------*/
fn sphincsv_sign_internal(
    context: &[u8],                  // context string
    message: &[u8],                  // message string
    sk: &[u8; PARAMS.spx_skbytes()], // secret key
    addrnd: &[u8; PARAMS.spx_n],     // additional randomness
) -> [u8; PARAMS.spx_sig()] {

    // declare the SPHINCS+V signature
    let mut sig_sphincsv: [u8; PARAMS.spx_sig()] = [0u8; PARAMS.spx_sig()];

    // separate the secret key components
    let mut sk_seed: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let mut sk_prf:  [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let mut pk_seed: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let mut pk_root: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    sk_seed.copy_from_slice(&sk[0*PARAMS.spx_n..1*PARAMS.spx_n]);
    sk_prf .copy_from_slice(&sk[1*PARAMS.spx_n..2*PARAMS.spx_n]);
    pk_seed.copy_from_slice(&sk[2*PARAMS.spx_n..3*PARAMS.spx_n]);
    pk_root.copy_from_slice(&sk[3*PARAMS.spx_n..4*PARAMS.spx_n]);

    // compute the message randomiser
    let r: [u8; PARAMS.spx_n] = prf_msg(&sk_prf, &addrnd, &context, &message);

    // write the message randomiser to the signature
    sig_sphincsv[0..PARAMS.spx_n].copy_from_slice(&r);

    // compute the message digest
    let digest: [u8; PARAMS.spx_m()] = h_msg(&r, &pk_seed, &pk_root, &context, &message);

    // extract md, tmp_idx_tree, and tmp_idx_leaf from digest
    let mut md:           [u8; PARAMS.spx_md_len()]       = [0u8; PARAMS.spx_md_len()];
    let mut tmp_idx_tree: [u8; PARAMS.spx_idx_tree_len()] = [0u8; PARAMS.spx_idx_tree_len()];
    let mut tmp_idx_leaf: [u8; PARAMS.spx_idx_leaf_len()] = [0u8; PARAMS.spx_idx_leaf_len()];
    md          .copy_from_slice(&digest[0                                             .. PARAMS.spx_md_len()                                                    ]);
    tmp_idx_tree.copy_from_slice(&digest[PARAMS.spx_md_len()                           .. PARAMS.spx_md_len()+PARAMS.spx_idx_tree_len()                          ]);
    tmp_idx_leaf.copy_from_slice(&digest[PARAMS.spx_md_len()+PARAMS.spx_idx_tree_len() .. PARAMS.spx_md_len()+PARAMS.spx_idx_tree_len()+PARAMS.spx_idx_leaf_len()]);

    // compute idx_tree and idx_leaf from tmp_idx_tree and tmp_idx_leaf
    let (idx_tree, idx_leaf) = parse_indices(tmp_idx_tree, tmp_idx_leaf);

    // initialise ADRS
    let mut adrs: Adrs = Adrs::new();

    // set the ADRS values for the PORS+FP signature generation
    adrs.set_tree_addr(idx_tree); // lowest-layer tree index of the XMSS tree that will sign the FORS public key
    adrs.set_type_and_clear(adrs_type::PORS_TREE);
    adrs.set_key_pair_addr(idx_leaf); // leaf index of the XMSS tree that will sign the FORS public key

    // compute the PORS+FP signature
    let sig_porsfp: [u8; PARAMS.porsfp_sig()] = porsfp_sign(&md, &sk_seed, &pk_seed, &mut adrs);

    // write the PORS+FP signature to the SPHINCS+V signature
    sig_sphincsv[PARAMS.spx_n..PARAMS.spx_n+PARAMS.porsfp_sig()].copy_from_slice(&sig_porsfp);

    // compute the PORS+FP public key based on the PORS+FP signature
    let _pk_porsfp: [u8; PARAMS.spx_n] = porsfp_pkfromsig(&sig_porsfp, &md, &pk_seed, &mut adrs);

    // compute the hypertree signature on the FORS public key
    // TODO
    // let sig_ht: [u8; PARAMS.ht_sig()] = ht_sign(&pk_porsfp, &sk_seed, &pk_seed, idx_tree, idx_leaf);
    let sig_ht: [u8; PARAMS.ht_sig()] = [0u8; PARAMS.ht_sig()];

    // write the PORS+FP signature to the SPHINCS+V signature
    sig_sphincsv[PARAMS.spx_n+PARAMS.porsfp_sig()..PARAMS.spx_n+PARAMS.porsfp_sig()+PARAMS.ht_sig()].copy_from_slice(&sig_ht);

    sig_sphincsv
}

/*-------------------------------------------------------------+
| ALGORITHM 22 FROM SLH-DSS (FIPS 205)                         |
| Generates a pure SPHINCS+V signature.                        |
| Generates the randomness needed for sphincsv_sign_internal   |
+-------------------------------------------------------------*/
pub fn sphincsv_sign (
    context: &[u8],                  // context string
    message: &[u8],                  // message string
    sk: &[u8; PARAMS.spx_skbytes()], // secret key
    deterministic: bool,             // whether to use addrnd = PK.seed (else addrnd = randombytes)
) -> [u8; PARAMS.spx_sig()] {

    // declare the additional randomness
    let mut addrnd: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    if deterministic {

        addrnd.copy_from_slice(&sk[2*PARAMS.spx_n..3*PARAMS.spx_n]);

    } else {

        // get a random number generator
        let mut rng: rand::prelude::ThreadRng = rand::rng();

        // generate the additional randomness
        addrnd = rng.random();

    }

    let sig_sphincsv: [u8; PARAMS.spx_sig()] = sphincsv_sign_internal(&context, &message, &sk, &addrnd);

    sig_sphincsv
}

/*-------------------------------------------------------------+
| ALGORITHM 20 FROM SLH-DSS (FIPS 205)                         |
| Verifies a SPHINCS+V signature.                              |
+-------------------------------------------------------------*/
fn sphincsv_verify_internal(
    _context: &[u8],                        // context string
    _message: &[u8],                        // message string
    _sig_sphincsv: &[u8; PARAMS.spx_sig()], // SPHINCS+V signature
    pk: &[u8; PARAMS.spx_pkbytes()],       // public key
) -> bool {

    // separate the public key components
    let mut pk_seed: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    let mut pk_root: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    pk_seed.copy_from_slice(&pk[0*PARAMS.spx_n..1*PARAMS.spx_n]);
    pk_root.copy_from_slice(&pk[1*PARAMS.spx_n..2*PARAMS.spx_n]);

    // TODO

    let res: bool = false;

    res
}

/*-------------------------------------------------------------+
| ALGORITHM 24 FROM SLH-DSS (FIPS 205)                         |
| Verifies a pure SPHINCS+V signature.                         |
+-------------------------------------------------------------*/
pub fn sphincsv_verify(
    context: &[u8],                        // context string
    message: &[u8],                        // message string
    sig_sphincsv: &[u8; PARAMS.spx_sig()], // SPHINCS+V signature
    pk: &[u8; PARAMS.spx_pkbytes()],       // public key
) -> bool {

    let res: bool = sphincsv_verify_internal(&context, &message, &sig_sphincsv, &pk);

    res
}



