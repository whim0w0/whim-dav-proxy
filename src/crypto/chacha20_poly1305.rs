use chacha20poly1305::Nonce;
use chacha20poly1305::aead::{Aead, KeyInit};
use sha2::{Digest, Sha256};

use crate::crypto::{BlockCipher, CYPTO_HEADER_SIZE, CYPTO_META_SIZE, Cipher};

pub const CP_BLOCK_SIZE: usize = 64 * 1024;

pub const CP_TAG_SIZE: usize = 16;

pub const CP_FRAME_SIZE: usize = CP_BLOCK_SIZE + CP_TAG_SIZE;

type ChaCha20Poly1305Cipher = chacha20poly1305::ChaCha20Poly1305;

pub struct ChaCha20Poly1305 {
    cipher: ChaCha20Poly1305Cipher,

    nonce: [u8; 16],

    counter: u32,
}

impl ChaCha20Poly1305 {
    fn derive_key(password: &[u8]) -> [u8; 32] {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(b"c20p1305-key-v1");

        hasher.update(password);
        let result: [u8; 32] = hasher.finalize().into();
        result
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        self.counter += 1;
        let mut n: [u8; 12] = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce[..8]);
        n[8..].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    fn boxed_new(password: &[u8]) -> Box<Self> {
        let key: [u8; 32] = Self::derive_key(password);

        let cipher: ChaCha20Poly1305Cipher =
            ChaCha20Poly1305Cipher::new_from_slice(&key).expect("32-byte key");

        let nonce: [u8; 16] = rand::random();
        Box::new(Self {
            cipher,
            nonce,
            counter: 0,
        })
    }

    fn boxed_parse(password: &[u8], header: [u8; CYPTO_HEADER_SIZE]) -> Box<Self> {
        let key: [u8; 32] = Self::derive_key(password);
        let mut nonce: [u8; 16] = [0u8; 16];
        nonce.copy_from_slice(&header[0..16]);
        let cipher: ChaCha20Poly1305Cipher =
            ChaCha20Poly1305Cipher::new_from_slice(&key).expect("32-byte key");
        Box::new(Self {
            cipher,
            nonce,
            counter: 0,
        })
    }
}

impl Cipher for ChaCha20Poly1305 {
    fn gen_header(&self) -> [u8; CYPTO_HEADER_SIZE] {
        let mut header: [u8; CYPTO_HEADER_SIZE] = [0u8; CYPTO_HEADER_SIZE];
        header[0..16].copy_from_slice(&self.nonce);
        header
    }

    fn plaintext_len_of(&self, cipher_len: u64) -> Option<u64> {
        let data: u64 = cipher_len.checked_sub(CYPTO_META_SIZE as u64)?;
        let fs: u64 = CP_FRAME_SIZE as u64;
        let bs: u64 = CP_BLOCK_SIZE as u64;
        let tag: u64 = CP_TAG_SIZE as u64;
        let n: u64 = data / fs;
        let r: u64 = data % fs;
        if r == 0 {
            Some(n * bs)
        } else if r >= tag {
            Some(n * bs + r - tag)
        } else {
            None
        }
    }

    fn map_plain_to_cipher(&self, plain_start: u64) -> (u64, usize) {
        let bs: u64 = CP_BLOCK_SIZE as u64;
        let fs: u64 = CP_FRAME_SIZE as u64;
        let block: u64 = plain_start / bs;

        let cipher_off: u64 = CYPTO_META_SIZE as u64 + block * fs;
        let skip: usize = (plain_start - block * bs) as usize;
        (cipher_off, skip)
    }

    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let n: [u8; 12] = self.next_nonce();
        let nonce: Nonce = n.into();
        self.cipher.encrypt(&nonce, data).unwrap_or_default()
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let n: [u8; 12] = self.next_nonce();
        let nonce: Nonce = n.into();
        self.cipher.decrypt(&nonce, data).unwrap_or_default()
    }
}

impl BlockCipher for ChaCha20Poly1305 {
    fn new_block_cipher(password: &[u8]) -> Box<dyn BlockCipher> {
        Self::boxed_new(password)
    }

    fn parse_block_cipher(
        password: &[u8],
        header: [u8; CYPTO_HEADER_SIZE],
    ) -> Box<dyn BlockCipher> {
        Self::boxed_parse(password, header)
    }

    fn frame_size(&self) -> usize {
        CP_FRAME_SIZE
    }

    fn plain_block_size(&self) -> usize {
        CP_BLOCK_SIZE
    }

    fn seek_to_block(&mut self, block: u64) {
        self.counter = block as u32;
    }
}
