
// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

// supporting modules
mod params;           // SPHINCS+V parameters
mod adrs;             // ADRS data structure
mod tweakable_hashes; // hash function instantiations
mod u256;             // WOTS+ parameter computation stuff

// algorithmic modules
mod porsfp;   // PORS+FP implementation
mod wots;     // WOTS+ implementation
mod xmss;     // XMSS implementation
mod ht;       // HT implementation
mod sphincsv; // SPHINCS+V implementation

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::porsfp::porsfp_node;
use crate::porsfp::porsfp_pkfromsig;
use crate::porsfp::porsfp_sign;
use crate::sphincsv::sphincsv_keygen;
use crate::sphincsv::sphincsv_sign;
use crate::sphincsv::sphincsv_verify;
use crate::tweakable_hashes::{prf_msg, h_msg}; // hash function instantiations

use crate::params::*;
use crate::wots::wots_pkfromsig;
use crate::wots::wots_pkgen;
use crate::wots::wots_sign;
use crate::xmss::xmss_node;
use crate::xmss::xmss_pkfromsig;
use crate::xmss::xmss_sign; // parameter values

// printing hex strings for debugging
fn print_hex(label: &str, bytes: &[u8]) {
    print!("{label}: ");
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            print!(" ");
        }
        print!("{byte:02x}");
    }
    println!();
}

fn main() {

    // let sk_seed: [u8; N] = [0x7F; N]; // set an sk_seed
    // let pk_seed: [u8; N] = [0xA1; N]; // set a  pk_seed

    // /* PORS+FP manual testing code */

    // println!();

    // // compute a PORS+FP public key from secret values
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_pors: [u8; N] = porsfp_node(&sk_seed, 0 as u32, H_BAR as u32, &pk_seed, adrs); // compute the PORS+FP public key
    // println!("PORS+FP node:        {:02x?}", pk_pors);

    // // compute a PORS+FP signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let md: [u8; N] = [0xCC; N]; // set an arbitrary message digest
    // let sig_porsfp: [u8; PORS_SIG] = porsfp_sign(&md, &sk_seed, &pk_seed, adrs); // compute a signature

    // // compute a PORS+FP public key from a signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_pors: [u8; N] = porsfp_pkfromsig(&sig_porsfp, &md, &pk_seed, adrs); // compute the PORS+FP public key
    // println!("PORS+FP pkfromsig 1: {:02x?}", pk_pors);

    // // compute a PORS+FP public key from a different message digest
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let md: [u8; N] = [0x65; N]; // set an arbitrary message digest
    // let sig_porsfp: [u8; PORS_SIG] = porsfp_sign(&md, &sk_seed, &pk_seed, adrs); // compute a signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_pors: [u8; N] = porsfp_pkfromsig(&sig_porsfp, &md, &pk_seed, adrs); // compute the PORS+FP public key
    // println!("PORS+FP pkfromsig 2: {:02x?}", pk_pors);

    // /* WOTS+ manual testing code */

    // println!();

    // // compute a WOTS+ public key from secret values
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_wots: [u8; N] = wots_pkgen(&sk_seed, &pk_seed, adrs); // compute the WOTS+ public key
    // println!("WOTS+ pkgen:         {:02x?}", pk_wots);

    // // compute a WOTS+ signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let m: [u8; N] = [0xCC; N]; // set an arbitrary message
    // let sig_wots: [u8; WOTS_SIG] = wots_sign(&m, &sk_seed, &pk_seed, adrs); // compute a signature

    // // compute a WOTS+ public key from a signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_wots: [u8; N] = wots_pkfromsig(&sig_wots, &m, &pk_seed, adrs); // compute the WOTS+ public key
    // println!("WOTS+ pkfromsig 1:   {:02x?}", pk_wots);

    // // compute a WOTS+ public key from a different message
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let m: [u8; N] = [0x65; N]; // set an arbitrary message
    // let sig_wots: [u8; WOTS_SIG] = wots_sign(&m, &sk_seed, &pk_seed, adrs); // compute a signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_wots: [u8; N] = wots_pkfromsig(&sig_wots, &m, &pk_seed, adrs); // compute the WOTS+ public key
    // println!("WOTS+ pkfromsig 2:   {:02x?}", pk_wots);

    // /* XMSS manual testing code */

    // println!();

    // // compute an XMSS public key from secret values
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_xmss: [u8; N] = xmss_node(&sk_seed, 0 as u32, H_PRIME as u32, &pk_seed, adrs); // compute the XMSS public key
    // println!("XMSS node:          {:02x?}", pk_xmss);

    // // compute an XMSS signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let m: [u8; N] = [0xCC; N]; // set an arbitrary message
    // let sig_xmss: [u8; XMSS_SIG] = xmss_sign(&m, &sk_seed, 5 as u32, &pk_seed, adrs); // compute a signature

    // // compute an XMSS public key from a signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_xmss: [u8; N] = xmss_pkfromsig(5 as u32, &sig_xmss, &m, &pk_seed, adrs); // compute the XMSS public key
    // println!("XMSS pkfromsig 1:   {:02x?}", pk_xmss);

    // // compute an XMSS public key from a different signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let m: [u8; N] = [0x65; N]; // set an arbitrary message
    // let sig_xmss: [u8; XMSS_SIG] = xmss_sign(&m, &sk_seed, 5 as u32, &pk_seed, adrs); // compute a signature
    // let adrs: Adrs = Adrs::new(); // initialise ADRS
    // let pk_xmss: [u8; N] = xmss_pkfromsig(5 as u32, &sig_xmss, &m, &pk_seed, adrs); // compute the XMSS public key
    // println!("XMSS pkfromsig 2:   {:02x?}", pk_xmss);



    /* SPHINCS+V manual testing code */

    println!();

    // compute a secret-public key pair
    let sk: [u8; SKBYTES];
    let pk: [u8; PKBYTES];
    (sk, pk) = sphincsv_keygen();
    // print_hex("sk", &sk);
    println!("keygen succes");

    // compute a SPHINCS+V signature
    let context: &[u8] = "SPHINCS+V test".as_bytes(); // create an abitrary context string
    let message: &[u8] = "Does this verify?".as_bytes(); // create an arbitrary message
    // println!("context: {:02x?}", context);
    // println!("message: {:02x?}", message);
    let sig_sphincsv:[u8; SPXV_SIG] = sphincsv_sign(&context, &message, &sk, true);
    println!("signing succes");
    
    // verify a SPHINCS+V signature
    let res: bool = sphincsv_verify(&context, &message, &sig_sphincsv, &pk);
    if res { println!("verification succes!\n"); } else { println!("verification failed :(\n"); }

}

