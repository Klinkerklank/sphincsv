
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

use crate::params::*; // parameter values

use crate::sphincsv::{sphincsv_keygen, sphincsv_sign, sphincsv_verify}; // top-level SPHINCS+V functions

fn main() {

    /* SPHINCS+V manual testing code */

    println!();

    // compute a secret-public key pair
    let sk: [u8; SKBYTES];
    let pk: [u8; PKBYTES];
    (sk, pk) = sphincsv_keygen();
    println!("keygen succes");

    // compute a SPHINCS+V signature
    let context: &[u8] = "SPHINCS+V test".as_bytes(); // create an abitrary context string
    let message: &[u8] = "Does this verify?".as_bytes(); // create an arbitrary message
    let sig_sphincsv:[u8; SPXV_SIG] = sphincsv_sign(&context, &message, &sk, true);
    println!("signing succes");
    
    // verify a SPHINCS+V signature
    let res: bool = sphincsv_verify(&context, &message, &sig_sphincsv, &pk);
    if res { println!("verification succes!\n"); } else { println!("verification failed :(\n"); }

}
