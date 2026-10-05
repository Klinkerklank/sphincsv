
// TODO remove after code is done
#![allow(dead_code)]

/*
 * SPHINCS+ ADRS structure
 * 
 * author: Dennis op 't Roodt 2026-10-02 (d.n.e.o.t.roodt@tue.nl)
 */

 // SPHINCS+ ADRS structure
#[derive(Clone, Copy)] // allows for cloning ADRS structures
pub struct Adrs {
    words: [u32; 8],
}

// ADRS functions for field accesses
impl Adrs {

    // initialise the structure to all zeroes
    pub fn new() -> Self {
        Self{
            words: [0; 8],
        }
    }

    // convert the ADRS to a Big-Endian byte string
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];

        for i in 0..8 {
            bytes[4 * i..4 * i + 4]
                .copy_from_slice(&self.words[i].to_be_bytes());
        }

        return bytes;
    }

    // compress ADRS to ADRS^c
    pub fn compress(&self) -> [u8; 22] {
        let adrs_bytes = self.to_bytes();
        let mut bytes = [0u8; 22];

        bytes[0] = adrs_bytes[3];
        bytes[1..9].copy_from_slice(&adrs_bytes[8..16]);
        bytes[9] = adrs_bytes[19];
        bytes[10..22].copy_from_slice(&adrs_bytes[20..32]);

        return bytes;
    }

    // set the layer address
    pub fn set_layer_addr(&mut self, layer_addr: u32) {
        self.words[0] = layer_addr;
    }

    // set the tree address
    pub fn set_tree_addr(&mut self, tree_addr: [u32; 3]) {
        self.words[1..4].copy_from_slice(&tree_addr);
    }

    // set the type, and reset the fields after type 
    pub fn set_type_and_clear(&mut self, adrs_type: u32) {
        self.words[4] = adrs_type;
        self.words[5..8].fill(0);
    }
    
    // set the key pair address
    pub fn set_key_pair_addr(&mut self, key_pair_addr: u32) {
        self.words[5] = key_pair_addr;
    }
    
    // set the chain address
    pub fn set_chain_addr(&mut self, chain_addr: u32) {
        self.words[6] = chain_addr;
    }
    
    // set the tree height
    pub fn set_tree_height(&mut self, tree_height: u32) {
        self.words[6] = tree_height;
    }
    
    // set the hash address
    pub fn set_hash_addr(&mut self, hash_addr: u32) {
        self.words[7] = hash_addr;
    }
    
    // set the tree index
    pub fn set_tree_index(&mut self, tree_index: u32) {
        self.words[7] = tree_index;
    }
    
    // get the key pair address
    pub fn get_key_pair_addr(&self) -> u32 {
        return self.words[5];
    }
    
    // get the tree index
    pub fn get_tree_index(&self) -> u32 {
        return self.words[7];
    }
    
}

// ADRS type field values
pub mod adrs_type {
    pub const WOTS_HASH: u32  = 0;
    pub const WOTS_PK: u32    = 1;
    pub const TREE: u32       = 2;
    pub const PORS_TREE: u32  = 3;
    pub const PORS_ROOTS: u32 = 4;
    pub const WOTS_PRF: u32   = 5;
    pub const PORS_PRF: u32   = 6;
}

