// TODO remove after code is done
#![allow(dead_code)]
#![allow(unused_imports)]

/*
 * HT algorithms, based on:
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
| ALGORITHM 12 FROM SLH-DSS (FIPS 205)                         |
| Generates a hypertree signature.                             |
+-------------------------------------------------------------*/
pub fn ht_sign(
    _pk_fors: [u8; PARAMS.spx_n], // message to sign (PORS+FP public key)
    _skseed: [u8; PARAMS.spx_n],  // SK.seed: secret seed
    _pkseed: [u8; PARAMS.spx_n],  // PK.seed: public seed
    _tree: [u32; 3],              // lowest-layer XMSS tree index
    _leaf: u32,                   // XMSS tree leaf index
) -> [u8; PARAMS.ht_sig()] // -> sig_ht
{



    let sig_ht: [u8; PARAMS.ht_sig()] = [0u8; PARAMS.ht_sig()];

    sig_ht
}

/*-------------------------------------------------------------+
| ALGORITHM 13 FROM SLH-DSS (FIPS 205)                         |
| Verifies a hypertree signature.                              |
+-------------------------------------------------------------*/
pub fn ht_verify(
    _pk_fors: [u8; PARAMS.spx_n],   // message to verify signature on (PORS+FP public key)
    _sig_ht: [u8; PARAMS.ht_sig()], // HT signature
    _pkseed: [u8; PARAMS.spx_n],    // PK.seed: public seed
    _tree: [u32; 3],                // lowest-layer XMSS tree index
    _leaf: u32,                     // XMSS tree leaf index
    _pkroot: [u8; PARAMS.spx_n],    // PK.root: hypertree root
) -> bool // -> whether the HT signature is correct w.r.t. PK.root
{



    let res: bool = false;

    res
}

