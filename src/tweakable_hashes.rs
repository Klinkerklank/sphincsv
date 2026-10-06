
// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * SPHINCS+V tweakable hash function instantiations
 * 
 * author: Dennis op 't Roodt 2026-10-05 (d.n.e.o.t.roodt@tue.nl)
 */

// SPHINCS+ ADRS structure

use crate::adrs::Adrs;     // ADRS data structure
use crate::params::PARAMS; // the SPHINCS+V parameters

use sha2::{Digest, Sha256};    // use SHA-2 for the hashing functions
use hmac::{Hmac, Mac};         // use the HMAC function for PRF_msg
use hmac::digest::KeyInit;     // for HMAC key initialisation
use std::collections::HashSet; // for sets instead of arrays

// SHA2 parameters
pub const SHA256_IN: usize  = 64;
pub const SHA256_OUT: usize = 32;

// helper for the first-block hash input setup
fn initialise_hash(
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
) -> Sha256 {

    // create the zero padding
    let zero_padding: [u8; SHA256_IN-PARAMS.spx_n] = [0u8; SHA256_IN-PARAMS.spx_n];

    // initialise the SHA-2 state
    let mut hash = Sha256::new();

    hash.update(pk_seed);      // absorb PK.seed
    hash.update(zero_padding); // absorb the zero padding

    hash
}

// H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
pub fn h_msg(
    r: &[u8; PARAMS.spx_n],       // message randomiser
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    pk_root: &[u8; PARAMS.spx_n], // PK.root
    context: &[u8],               // context string
    message: &[u8],               // message to be signed
) -> [u8; PARAMS.spx_m()] {

    // initialise the SHA-2 state
    let mut hash = Sha256::new();

    // absorb all inputs for the inner hash
    hash.update(r);                     // absorb the message randomiser
    hash.update(pk_seed);               // absorb PK.seed
    hash.update(pk_root);               // absorb PK.root
    hash.update([0u8]);                 // absorb domain separator byte
    hash.update([context.len() as u8]); // absorb the context length
    hash.update(context);               // absorb the context string
    hash.update(message);               // absorb the message to be signed

    let digest = hash.finalize(); // finalise the digest

    // construct the MGF1 seed (R || PK.seed || digest || counter)
    let mut seed: Vec<u8> = Vec::with_capacity(2*PARAMS.spx_n + SHA256_OUT + 4);
    seed.extend_from_slice(r);         // set the message randomiser
    seed.extend_from_slice(pk_seed);   // set PK.seed
    seed.extend_from_slice(&digest);   // set the digest from the inner hash
    seed.extend_from_slice(&[0u8; 4]); // set the counter, initially zero

    // get the required number of hash outputs
    let num_hashes: usize = (PARAMS.spx_m() + SHA256_OUT - 1) / SHA256_OUT;

    // declare the output array
    let mut out: [u8; PARAMS.spx_m()] = [0u8; PARAMS.spx_m()];

    for hash_nr in 0..num_hashes {

        let counter: [u8; 4] = (hash_nr as u32).to_be_bytes(); // MGF1 counter is a 32-bit big-endian integer
        seed[2 * PARAMS.spx_n + SHA256_OUT..].copy_from_slice(&counter); // write the counter to the input buffer

        let mut hash = Sha256::new(); // initialise the SHA-2 state

        hash.update(&seed); // absorb the entire seed buffer

        let digest = hash.finalize(); // finalise the digest

        let offset: usize = hash_nr * SHA256_OUT;             // find the offset to write to in the output array
        let remaining: usize = PARAMS.spx_m() - offset;       // compute how many bytes are left to fill
        let bytes_to_copy: usize = remaining.min(SHA256_OUT); // compute how many bytes to copy to the output

        // copy (and truncate) the digest to the output
        out[offset..offset + bytes_to_copy].copy_from_slice(&digest[..bytes_to_copy]);
    }

    out
}

// PRF_msg(SK.prf, optrand, M) = Trunc_n(HMAC-SHA-256(SK.prf, optrand || M))
pub fn prf_msg(
    sk_prf: &[u8; PARAMS.spx_n],  // SK.prf
    optrand: &[u8; PARAMS.spx_n], // (optional) additional randomness
    context: &[u8],               // context string
    message: &[u8],               // message to be signed
) -> [u8; PARAMS.spx_n] {
    type HmacSha256 = Hmac<Sha256>;

    // initialise the HMAC with SK.prf as key
    let mut mac = HmacSha256::new_from_slice(sk_prf).expect("Invalid HMAC key length");

    mac.update(optrand);                // absorb additional randomness
    mac.update(&[0u8]);                 // absorb the domain separator byte
    mac.update(&[context.len() as u8]); // absorb context length
    mac.update(context);                // absorb context string
    mac.update(message);                // absorb message to be signed

    let hmac = mac.finalize().into_bytes(); // finalise the digest

    // truncate the digest to PARAMS.spx_n bytes
    let mut trunc: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    trunc.copy_from_slice(&hmac[..PARAMS.spx_n]);

    trunc
}

// PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRS^c || SK.seed))
pub fn prf(
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    adrs: &Adrs,                  // ADRS
) -> [u8; PARAMS.spx_n] {

    // hash input setup
    let adrsc: [u8; 22] = adrs.compress(); // compress ADRS to ADRS^c
    
    // process the first block of input
    let mut hash = initialise_hash(pk_seed);
    
    // absorb all remaining inputs
    hash.update(adrsc);   // absorb ADRS^c
    hash.update(sk_seed); // absorb SK.seed

    // finalise the digest computation
    let digest = hash.finalize();

    // truncate the digest to PARAMS.spx_n bytes
    let mut trunc: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    trunc.copy_from_slice(&digest[..PARAMS.spx_n]);

    // return the truncated digest
    trunc
}

// F(PK.seed, ADRS, M_1) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRS^c || M_1))
pub fn f(
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &Adrs,                  // ADRS
    m: &[u8; PARAMS.spx_n],       // input message
) -> [u8; PARAMS.spx_n] {

    // hash input setup
    let adrsc: [u8; 22] = adrs.compress(); // compress ADRS to ADRS^c
    
    // process the first block of input
    let mut hash = initialise_hash(pk_seed);
    
    // absorb all remaining inputs
    hash.update(adrsc); // absorb ADRS^c
    hash.update(m);     // absorb M1

    // finalise the digest computation
    let digest = hash.finalize();

    // truncate the digest to PARAMS.spx_n bytes
    let mut trunc: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    trunc.copy_from_slice(&digest[..PARAMS.spx_n]);

    // return the truncated digest
    trunc
}

// H(PK.seed, ADRS, M_2) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRS^c || M_2))
pub fn h(
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &Adrs,                  // ADRS
    m1: &[u8; PARAMS.spx_n],      // 1st input message
    m2: &[u8; PARAMS.spx_n],      // 2nd input message
) -> [u8; PARAMS.spx_n] {

    // hash input setup
    let adrsc: [u8; 22] = adrs.compress(); // compress ADRS to ADRS^c
    
    // process the first block of input
    let mut hash = initialise_hash(pk_seed);
    
    // absorb all remaining inputs
    hash.update(adrsc); // absorb ADRS^c
    hash.update(m1);    // absorb M1
    hash.update(m2);    // absorb M2

    // finalise the digest computation
    let digest = hash.finalize();

    // truncate the digest to PARAMS.spx_n bytes
    let mut trunc: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    trunc.copy_from_slice(&digest[..PARAMS.spx_n]);

    // return the truncated digest
    trunc
}

// H_2(PK.seed, ADRS, md, ctr) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRS^c || md || ctr))
pub fn h2(
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &Adrs,                  // ADRS
    md: &[u8; PARAMS.spx_n],      // message digest
    ctr: u32,                     // counter
) -> Vec<u32> { // -> set of k unique indices = 0..(t choose k)

    // hash input setup
    let adrsc: [u8; 22] = adrs.compress(); // compress ADRS to ADRS^c
    
    // process the first block of input
    let mut hash = initialise_hash(pk_seed);
    
    // absorb all remaining inputs
    hash.update(adrsc);             // absorb ADRS^c
    hash.update(md);                // absorb md
    hash.update(ctr.to_be_bytes()); // absorb ctr

    // finalise the digest computation
    let digest = hash.finalize();

    // TODO how to map to (t choose k)?
    let indices: Vec<u32> = vec![0u32; PARAMS.spx_k];

    indices
}

// T_len(PK.seed, ADRS, M_len) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRS^c || M_len))
pub fn t_len(
    pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    adrs: &Adrs,                  // ADRS
    chains: &[u8; PARAMS.spx_len()*PARAMS.spx_n], // concatenation of all chain end values in a WOTS instance
) -> [u8; PARAMS.spx_n] {

    // hash input setup
    let adrsc: [u8; 22] = adrs.compress(); // compress ADRS to ADRS^c
    
    // process the first block of input
    let mut hash = initialise_hash(pk_seed);
    
    // absorb all remaining inputs
    hash.update(adrsc);  // absorb ADRS^c
    hash.update(chains); // absorb all chain values

    // finalise the digest computation
    let digest = hash.finalize();

    // truncate the digest to PARAMS.spx_n bytes
    let mut trunc: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];
    trunc.copy_from_slice(&digest[..PARAMS.spx_n]);

    // return the truncated digest
    trunc
}

