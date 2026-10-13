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

use crate::tweakable_hashes::{f, t_v}; // hash function instantiations

use crate::u256::*; // WOTS+ parameter computation stuff

/////////////////////// HELPER FUNCTIONS ///////////////////////
 
fn map_to_vertex(
    _x: usize, // input message
) -> [usize; PARAMS.spx_v()] {

    // 1. set x_i = x and d_1 = PARAMS.d0

    // 2. for i from 1 to v-1:

    // 2a. find j_i in {0, ..., w-1} s.t. sum_{0<=j<j_i} l_{d_i-j}^{<v-i>} <= x_i < sum_{0<=j<=j_i} l_{d_i-j}^{<v-i>}

    // 2b. set a_i = w - j_i in [w]

    // 2c. set d_{i+1} = d_i - j_i = d_i - (w - a_i)

    // 2d. set x_{i+1} = x_i - sum_{0<=j<j} l_{d_i-j}^{<v-i>}

    // 3. set a_v = w - x_v - d_v

    // 4. output (a_1, a_2, ..., a_v)

    let a: [usize; PARAMS.spx_v()] = [0; PARAMS.spx_v()];

    a
    
}
 
fn top_single_layer(
    _msg: [u8; PARAMS.spx_n], // input message
) -> [usize; PARAMS.spx_v()] {

    // translate msg to x, which is in {0, 1, ..., w^v-1}

    // rescale msg (almost) uniformly onto [0..l_{PARAMS.d0}]
    // x = floor(msg*l_{PARAMS.d0} / w^v)

    // output a = map_to_vertex(x)

    let a: [usize; PARAMS.spx_v()] = [0; PARAMS.spx_v()];

    a

}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 5 FROM SLH-DSS (FIPS 205)                          |
| Chaining function used in WOTS+.                             |
+-------------------------------------------------------------*/
fn chain(
    mut _out: [u8; PARAMS.spx_n],  // out: hash of previous chain value (also input: chain is in-place)
    _i: u32,                       // position in the chain
    _steps: u32,                   // number of hash evaluations to do
    _pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,               // ADRS
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
    _sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    _pk_seed: &[u8; PARAMS.spx_n], // PK.seed
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
    _m: &[u8; PARAMS.spx_n],       // message to sign (XMSS tree root or PORS+FP public key)
    _sk_seed: &[u8; PARAMS.spx_n], // SK.seed
    _pk_seed: &[u8; PARAMS.spx_n], // PK.seed
    mut _adrs: Adrs,               // ADRS
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
    _sig_wots: &[u8; PARAMS.wots_sig()], // WOTS+ signature
    _m: &[u8; PARAMS.spx_n],             // message (XMSS root or FORS public key)
    _pk_seed: &[u8; PARAMS.spx_n],       // PK.seed
    mut _adrs: Adrs,                     // ADRS
) -> [u8; PARAMS.spx_n] // -> pk_wots
{



    let pk_wots: [u8; PARAMS.spx_n] = [0u8; PARAMS.spx_n];

    pk_wots
}