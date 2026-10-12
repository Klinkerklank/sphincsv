// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * WOTS+ algorithms, based on:
 * [KKW25] Khovratovich, D., Kudinov, M. and Wagner, B., 'At the Top of the Hypercube - Better Size-Time Tradeoffs for Hash-Based Signatures', Aug 2025
 * [QSZ26] Qin, Z., Sun, S. and Zheng, F., 'Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths', Oct 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::params::PARAMS;  // the SPHINCS+V parameters
use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants
use crate::tweakable_hashes::{}; // hash function instantiations

/////////////////////// HELPER FUNCTIONS ///////////////////////

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 5 FROM SLH-DSS (FIPS 205)                          |
| Chaining function used in WOTS+.                             |
+-------------------------------------------------------------*/
fn chain(
    mut _out: [u8; PARAMS.spx_n], // out: hash of previous chain value (also input: chain is in-place)
    _i: u32,                      // position in the chain
    _steps: u32,                  // number of hash evaluations to do
    _pkseed: &[u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,              // ADRS
) -> [u8; PARAMS.spx_n] // -> out
{



    _out = [0u8; PARAMS.spx_n];

    _out
}

/*-------------------------------------------------------------+
| ALGORITHM 6 FROM SLH-DSS (FIPS 205)                          |
| Generates a WOTS+ public key.                                |
+-------------------------------------------------------------*/
pub fn wots_pkgen(
    _skseed: &[u8; PARAMS.spx_n], // SK.seed
    _pkseed: &[u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,               // ADRS
) -> [u8; PARAMS.spx_n] // -> pk
{



    let pk: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    pk
}

/*-------------------------------------------------------------+
| ALGORITHM 7 FROM SLH-DSS (FIPS 205)                          |
| Generates a WOTS+ signature on an n-byte message.            |
+-------------------------------------------------------------*/
pub fn wots_sign(
    _m: &[u8; PARAMS.spx_n],      // message to sign (XMSS tree root or PORS+FP public key)
    _skseed: &[u8; PARAMS.spx_n], // SK.seed
    _pkseed: &[u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,              // ADRS
) -> [u8; PARAMS.wots_sig()] // -> sig_wots
{



    let sig_wots: [u8; PARAMS.wots_sig()] = [0u8; PARAMS.wots_sig()];

    sig_wots
}

/*-------------------------------------------------------------+
| ALGORITHM 8 FROM SLH-DSS (FIPS 205)                          |
| Computes a WOTS+ public key from a message and its           |
| signature.                                                   |
+-------------------------------------------------------------*/
pub fn wots_pkfromsig(
    _sig_wots: [u8; PARAMS.wots_sig()], // WOTS+ signature
    _m: &[u8; PARAMS.spx_n],            // message (XMSS root or FORS public key)
    _pkseed: &[u8; PARAMS.spx_n],       // PK.seed
    mut _adrs: Adrs,                    // ADRS
) -> [u8; PARAMS.spx_n] // -> pk_wots
{



    let pk_wots: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    pk_wots
}