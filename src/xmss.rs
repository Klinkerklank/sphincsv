// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * XMSS algorithms
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
| ALGORITHM 9 FROM SLH-DSS (FIPS 205)                          |
| Computes the root of a Merkle subtree of WOTS+ public keys.  |
| (iterative instead of recursive)                             |
+-------------------------------------------------------------*/
pub fn xmss_node(
    _skseed: [u8; PARAMS.spx_n], // SK.seed
    _i: u32,                     // target node index (horizontal)
    _z: u32,                     // target node height
    _pkseed: [u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,             // ADRS
) -> [u8; PARAMS.spx_n] // -> root
{



    let root: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    root
}

/*-------------------------------------------------------------+
| ALGORITHM 10 FROM SLH-DSS (FIPS 205)                         |
| Generates an XMSS signature.                                 |
+-------------------------------------------------------------*/
pub fn xmss_sign(
    _m: [u8; PARAMS.spx_n],      // message to sign (XMSS public key or FORS public key)
    _skseed: [u8; PARAMS.spx_n], // SK.seed
    _idx: u32,                   // WOTS+ leaf index to sign with
    _pkseed: [u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,             // ADRS
) -> [u8; PARAMS.xmss_sig()] // -> sig_xmss
{



    let sig_xmss: [u8; PARAMS.xmss_sig()] = [0u8; PARAMS.xmss_sig()];

    sig_xmss
}

/*-------------------------------------------------------------+
| ALGORITHM 11 FROM SLH-DSS (FIPS 205)                         |
| Computes an XMSS public key from an XMSS signature.          |
+-------------------------------------------------------------*/
pub fn xmss_pkfromsig(
    _idx: u32,                          // WOTS+ leaf index to sign with
    _sig_xmss: [u8; PARAMS.xmss_sig()], // XMSS signature
    _m: [u8; PARAMS.spx_n],             // message to sign (XMSS public key or FORS public key)
    _pkseed: [u8; PARAMS.spx_n],        // PK.seed
    mut _adrs: Adrs,                    // ADRS
) -> [u8; PARAMS.spx_n] // -> pk_xmss
{



    let pk_xmss: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    pk_xmss
}

