/*
 * 256-bit operations, used mainly in computating the WOTS+ parameters
 * 
 * author: Dennis op 't Roodt 2026-10-13 (d.n.e.o.t.roodt@tue.nl)
 */

pub type U256 = [u64; 4]; // little-endian limbs
pub const ZERO: U256 = [0; 4];

pub const fn u256_add(a: U256, b: U256) -> U256 {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = c1 as u64 + c2 as u64;
        i += 1;
    }
    assert!(carry == 0, "U256 overflow");
    r
}

pub const fn u256_sub(a: U256, b: U256) -> U256 {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = b1 as u64 + b2 as u64;
        i += 1;
    }
    assert!(borrow == 0);
    r
}

pub const fn bit_len(x: U256) -> usize {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if x[i] != 0 {
            return 64 * i + (64 - x[i].leading_zeros() as usize);
        }
    }
    0
}

// search window for d0; must exceed v*(w-1)/2 to see the middle layer
const MAX_E: usize = 512;

// Minimum d with l_d^{<v>} >= 2^lambda, or None if no layer is that large.
pub const fn d0_for(lg_w: usize, v: usize, lambda: usize) -> Option<usize> {
    let w = 1usize << lg_w;
    let mut row = [[0u64; 4]; MAX_E];
    let mut e = 0;
    while e < w && e < MAX_E { row[e] = [1, 0, 0, 0]; e += 1; }   // k = 1

    let mut k = 2;
    while k <= v {
        let mut new = [[0u64; 4]; MAX_E];
        new[0] = row[0];
        let mut e = 1;
        while e < MAX_E {
            let mut s = u256_add(new[e - 1], row[e]);
            if e >= w { s = u256_sub(s, row[e - w]); }
            new[e] = s;
            e += 1;
        }
        row = new;
        k += 1;
    }

    let mut e = 0;
    while e < MAX_E {
        if bit_len(row[e]) > lambda { return Some(e); }   // l_e >= 2^lambda
        e += 1;
    }
    None
}

pub const fn u256_lt(a: &U256, b: &U256) -> bool {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] { return a[i] < b[i]; }
    }
    false
}

/// big-endian bytes (<= 32) -> U256
pub fn u256_from_be(bytes: &[u8]) -> U256 {
    assert!(bytes.len() <= 32);
    let mut r = ZERO;
    for (i, &b) in bytes.iter().rev().enumerate() {
        r[i / 8] |= (b as u64) << (8 * (i % 8));
    }
    r
}

/// 256x256 -> 512-bit product
pub fn mul_wide(a: &U256, b: &U256) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + carry;
            r[i + j] = t as u64;
            carry = t >> 64;
        }
        r[i + 4] = carry as u64;
    }
    r
}

/// (r >> bits) truncated to 256 bits
pub fn shr_to_u256(r: &[u64; 8], bits: usize) -> U256 {
    let (limb, sh) = (bits / 64, bits % 64);
    let mut out = ZERO;
    for i in 0..4 {
        let lo = if i + limb < 8 { r[i + limb] } else { 0 };
        let hi = if i + limb + 1 < 8 { r[i + limb + 1] } else { 0 };
        out[i] = if sh == 0 { lo } else { (lo >> sh) | (hi << (64 - sh)) };
    }
    out
}

