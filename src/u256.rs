/*
 * 256-bit operations, used in computing the WOTS+ parameters
 * 
 * author: Dennis op 't Roodt 2026-10-15 (d.n.e.o.t.roodt@tue.nl)
 */

////////////////////// TYPE AND CONSTANTS //////////////////////

pub type U256 = [u64; 4];                // little-endian limbs, limb 0 is least significant
pub const U256_ZERO: U256 = [0; 4];      // U256 value 0
pub const U256_ONE: U256 = [1, 0, 0, 0]; // U256 value 1

/////////////////////// HELPER FUNCTIONS ///////////////////////

// U256 addition: computes a + b, panics if the sum does not fit in 256 bits
pub const fn u256_add(
    a: U256, // first input
    b: U256, // second input
) -> U256 { // -> a + b

    let mut r: U256 = [0u64; 4];  // declare output sum
    let mut carry: u64 = 0;       // carry into the next limb
    let mut i: usize = 0;

    // add limb by limb, from least to most significant
    while i < 4 {

        // a limb sum can overflow twice: once adding b[i], once adding the incoming carry
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);

        r[i] = s2;
        carry = c1 as u64 + c2 as u64; // at most 1, since both overflows cannot happen together

        i += 1;

    }

    // a carry out of the top limb means the sum is >= 2^256
    assert!(carry == 0, "U256 overflow");

    r
}

// U256 subtraction: computes a - b, panics if b > a
pub const fn u256_sub(
    a: U256, // first input
    b: U256, // second input
) -> U256 { // -> a - b

    let mut r: U256 = [0u64; 4];  // declare output difference
    let mut borrow: u64 = 0;      // borrow from the next limb
    let mut i: usize = 0;

    // subtract limb by limb, from least to most significant
    while i < 4 {

        // a limb difference can underflow twice: once subtracting b[i], once the incoming borrow
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);

        r[i] = d2;
        borrow = b1 as u64 + b2 as u64; // at most 1, since both underflows cannot happen together

        i += 1;

    }

    // a borrow out of the top limb means b > a
    assert!(borrow == 0);

    r
}

// U256 comparison: checks whether a < b
pub const fn u256_lt(
    a: &U256, // first input
    b: &U256, // second input
) -> bool { // -> a < b

    let mut i: usize = 4;

    // compare limbs from most to least significant, the first difference decides
    while i > 0 {

        i -= 1;
        if a[i] != b[i] { return a[i] < b[i]; }

    }

    false // all limbs equal, so a == b
}

// U256 bit length: computes the number of bits needed to write x
pub const fn u256_bitlen(
    x: U256, // value to measure
) -> usize { // -> 0 for x == 0, else floor(log2(x)) + 1

    let mut i: usize = 4;

    // find the most significant non-zero limb
    while i > 0 {

        i -= 1;

        if x[i] != 0 {
            return 64 * i + (64 - x[i].leading_zeros() as usize); // full limbs below + bits used in this limb
        }

    }

    0 // x == 0
}

// big-endian bytes to U256: right-aligns the bytes, i.e. the last byte is the least significant byte of the result
pub fn u256_from_be(
    bytes: &[u8], // big-endian bytes, at most 32
) -> U256 { // -> the integer encoded by the bytes

    assert!(bytes.len() <= 32);

    let mut r: U256 = U256_ZERO; // declare output integer

    // walk from the least significant byte upwards
    for (i, &b) in bytes.iter().rev().enumerate() {

        r[i / 8] |= (b as u64) << (8 * (i % 8)); // byte i goes to limb i/8, at byte offset i%8

    }

    r
}

// wide multipliciation: computes the full 256x256 -> 512-bit product
pub fn u256_mul_wide(
    a: &U256, // first factor
    b: &U256, // second factor
) -> [u64; 8] { // -> a * b as 8 little-endian limbs, never overflows

    let mut r: [u64; 8] = [0u64; 8]; // declare output product

    for i in 0..4 {

        let mut carry: u128 = 0;

        // add a[i] * b to the product, shifted by i limbs
        for j in 0..4 {

            // cannot overflow u128: (2^64-1)^2 + 2 * (2^64-1) < 2^128
            let t: u128 = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + carry;

            r[i + j] = t as u64;
            carry = t >> 64;

        }

        r[i + 4] = carry as u64; // this limb has not been written yet, so no addition is needed

    }

    r
}

// shift right and truncate: computes (r >> bits), keeping only the low 256 bits
pub fn shr_to_u256(
    r: &[u64; 8], // 512-bit value, little-endian limbs
    bits: usize,  // shift number in bits
) -> U256 { // -> (r >> bits) mod 2^256

    // declare output value
    let mut out: U256 = U256_ZERO;

    // whole-limb shift, and remaining shift within a limb
    let (limb, sh): (usize, usize) = (bits / 64, bits % 64);

    for i in 0..4 {

        // limbs shifted in from beyond the top of r are 0
        let lo: u64 = if i + limb < 8 { r[i + limb] } else { 0 };
        let hi: u64 = if i + limb + 1 < 8 { r[i + limb + 1] } else { 0 };

        // for sh == 0 the (64 - sh) shift would be out of range, so that case is handled separately
        out[i] = if sh == 0 { lo } else { (lo >> sh) | (hi << (64 - sh)) };

    }

    out
}

//////////////////////// MAIN FUNCTIONS ////////////////////////

// search window for d0, must exceed v*(w-1)/2 to see the middle layer
const MAX_E: usize = 512;

/*-------------------------------------------------------------+
| 'FIND THE MINIMUM d0' FROM CONSTRUCTION 5 OF [KKW25]         |
| Finds the minimum d with l_D0^{<V>} >= 2^LAMBDA.             |
+-------------------------------------------------------------*/
pub const fn wots_find_d0(
    w: usize,      // Winternitz parameter
    v: usize,      // number of chains
    lambda: usize, // security parameter
) -> Option<usize> { // -> Some(d_0), or None if no layer within MAX_E is that large

    // row holds l_e^{<k>} for e in 0..MAX_E, for the current chain count k
    let mut row: [U256; MAX_E] = [U256_ZERO; MAX_E];

    // k = 0: one chain, so exactly one way for each budget 0..W-1, none above
    let mut e: usize = 0;
    while e < w && e < MAX_E { row[e] = U256_ONE; e += 1; }

    // k = 1..V: each row is built from the previous one
    let mut k: usize = 1;
    while k < v {

        let mut new: [U256; MAX_E] = [U256_ZERO; MAX_E];

        // budget 0: every chain must take j = 0, so there is exactly one way
        new[0] = row[0];

        // sliding window: l_e^{<k>} = l_{e-1}^{<k>} + l_e^{<k-1>} - l_{e-W}^{<k-1>}
        let mut e: usize = 1;
        while e < MAX_E {

            let mut s: U256 = u256_add(new[e - 1], row[e]); // shift the window by one, adding the new term on its right edge
            if e >= w { s = u256_sub(s, row[e - w]); }      // drop the term that just left the window on the left edge
            new[e] = s;

            e += 1;

        }

        row = new;
        k += 1;

    }

    // the first layer d with l_d >= 2^lambda, i.e. with more than lambda bits
    let mut e: usize = 0;
    while e < MAX_E {

        if u256_bitlen(row[e]) > lambda { return Some(e); } // l_e >= 2^lambda
        e += 1;

    }

    None
}
