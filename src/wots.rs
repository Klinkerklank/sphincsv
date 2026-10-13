/*
 * WOTS+ algorithms, based on:
 * [KKW25] Khovratovich, D., Kudinov, M. and Wagner, B., 'At the Top of the Hypercube - Better Size-Time Tradeoffs for Hash-Based Signatures', Aug 2025
 * [QSZ26] Qin, Z., Sun, S. and Zheng, F., 'Extending the SPHINCS+ Framework: Varying the Tree Heights and Chain Lengths', Oct 2026
 * adapated to work with SPHINCS+
 * 
 * author: Dennis op 't Roodt 2026-10-12 (d.n.e.o.t.roodt@tue.nl)
 */

use crate::adrs::Adrs;      // ADRS data structure
use crate::adrs::adrs_type; // ADRS type constants

use crate::params::{N, V, WOTS_SIG}; // parameter values

use crate::tweakable_hashes::{f, t_v}; // hash function instantiations

use crate::u256::*; // WOTS+ parameter computation stuff

/////////////////////// HELPER FUNCTIONS ///////////////////////
 
fn map_to_vertex(
    _x: usize, // input message
) -> [usize; V] {

    // 1. set x_i = x and d_1 = PARAMS.d0

    // 2. for i from 1 to v-1:

    // 2a. find j_i in {0, ..., w-1} s.t. sum_{0<=j<j_i} l_{d_i-j}^{<v-i>} <= x_i < sum_{0<=j<=j_i} l_{d_i-j}^{<v-i>}

    // 2b. set a_i = w - j_i in [w]

    // 2c. set d_{i+1} = d_i - j_i = d_i - (w - a_i)

    // 2d. set x_{i+1} = x_i - sum_{0<=j<j} l_{d_i-j}^{<v-i>}

    // 3. set a_v = w - x_v - d_v

    // 4. output (a_1, a_2, ..., a_v)

    let a: [usize; V] = [0; V];

    a
    
}
 
fn top_single_layer(
    _msg: [u8; N], // input message
) -> [usize; V] {

    // translate msg to x, which is in {0, 1, ..., w^v-1}

    // rescale msg (almost) uniformly onto [0..l_{PARAMS.d0}]
    // x = floor(msg*l_{PARAMS.d0} / w^v)

    // output a = map_to_vertex(x)

    let a: [usize; V] = [0; V];

    a

}

//////////////////////// MAIN FUNCTIONS ////////////////////////

/*-------------------------------------------------------------+
| ALGORITHM 5 FROM SLH-DSS (FIPS 205)                          |
| Chaining function used in WOTS+.                             |
+-------------------------------------------------------------*/
fn chain(
    mut _out: [u8; N],  // out: hash of previous chain value (also input: chain is in-place)
    _i: u32,                       // position in the chain
    _steps: u32,                   // number of hash evaluations to do
    _pk_seed: &[u8; N], // PK.seed
    mut _adrs: Adrs,               // ADRS
) -> [u8; N] // -> out
{



    _out = [0u8; N];

    _out
}

/*-------------------------------------------------------------+
| ALGORITHM 6 FROM SLH-DSS (FIPS 205)                          |
| Generates a WOTS+ public key.                                |
+-------------------------------------------------------------*/
pub fn wots_pkgen(
    _sk_seed: &[u8; N], // SK.seed
    _pk_seed: &[u8; N], // PK.seed
    mut _adrs: Adrs,               // ADRS
) -> [u8; N] // -> pk
{



    let pk: [u8; N] = [0u8; N];

    pk
}

/*-------------------------------------------------------------+
| ALGORITHM 7 FROM SLH-DSS (FIPS 205)                          |
| Generates a WOTS+ signature on an n-byte message.            |
+-------------------------------------------------------------*/
pub fn wots_sign(
    _m: &[u8; N],       // message to sign (XMSS tree root or PORS+FP public key)
    _sk_seed: &[u8; N], // SK.seed
    _pk_seed: &[u8; N], // PK.seed
    mut _adrs: Adrs,               // ADRS
) -> [u8; WOTS_SIG] // -> sig_wots
{



    let sig_wots: [u8; WOTS_SIG] = [0u8; WOTS_SIG];

    sig_wots
}

/*-------------------------------------------------------------+
| ALGORITHM 8 FROM SLH-DSS (FIPS 205)                          |
| Computes a WOTS+ public key from a message and its           |
| signature.                                                   |
+-------------------------------------------------------------*/
pub fn wots_pkfromsig(
    _sig_wots: &[u8; WOTS_SIG], // WOTS+ signature
    _m: &[u8; N],             // message (XMSS root or FORS public key)
    _pk_seed: &[u8; N],       // PK.seed
    mut _adrs: Adrs,                     // ADRS
) -> [u8; N] // -> pk_wots
{



    let pk_wots: [u8; N] = [0u8; N];

    pk_wots
}