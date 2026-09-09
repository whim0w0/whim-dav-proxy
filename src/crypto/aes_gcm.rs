use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::aead::{Aead, KeyInit};
use sha2::{Digest, Sha256};

use crate::crypto::{BlockCipher, CYPTO_HEADER_SIZE, CYPTO_META_SIZE, Cipher};

pub const GCM_BLOCK_SIZE: usize = 64 * 1024;

pub const GCM_TAG_SIZE: usize = 16;

pub const GCM_FRAME_SIZE: usize = GCM_BLOCK_SIZE + GCM_TAG_SIZE;

pub struct AesGcm {
    cipher: Aes256Gcm,

    nonce: [u8; 16],

    counter: u32,
}

type Aes256Gcm = aes_gcm::Aes256Gcm;

impl AesGcm {
    fn derive_key(password: &[u8]) -> [u8; 32] {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(b"aesgcm-key-v1");

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

        let cipher: Aes256Gcm = Aes256Gcm::new_from_slice(&key).expect("AES-256 key");

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
        let cipher: Aes256Gcm = Aes256Gcm::new_from_slice(&key).expect("AES-256 key");
        Box::new(Self {
            cipher,
            nonce,
            counter: 0,
        })
    }
}

impl Cipher for AesGcm {
    fn gen_header(&self) -> [u8; CYPTO_HEADER_SIZE] {
        let mut header: [u8; CYPTO_HEADER_SIZE] = [0u8; CYPTO_HEADER_SIZE];
        header[0..16].copy_from_slice(&self.nonce);
        header
    }

    fn plaintext_len_of(&self, cipher_len: u64) -> Option<u64> {
        let data: u64 = cipher_len.checked_sub(CYPTO_META_SIZE as u64)?;
        let fs: u64 = GCM_FRAME_SIZE as u64;
        let bs: u64 = GCM_BLOCK_SIZE as u64;
        let tag: u64 = GCM_TAG_SIZE as u64;
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
        let bs: u64 = GCM_BLOCK_SIZE as u64;
        let fs: u64 = GCM_FRAME_SIZE as u64;
        let block: u64 = plain_start / bs;

        let cipher_off: u64 = CYPTO_META_SIZE as u64 + block * fs;
        let skip: usize = (plain_start - block * bs) as usize;
        (cipher_off, skip)
    }

    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let n: [u8; 12] = self.next_nonce();
        let nonce: GenericArray<u8, U12> = GenericArray::from_slice(&n).clone();
        self.cipher.encrypt(&nonce, data).unwrap_or_default()
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let n: [u8; 12] = self.next_nonce();
        let nonce: GenericArray<u8, U12> = GenericArray::from_slice(&n).clone();
        self.cipher.decrypt(&nonce, data).unwrap_or_default()
    }
}

impl BlockCipher for AesGcm {
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
        GCM_FRAME_SIZE
    }

    fn plain_block_size(&self) -> usize {
        GCM_BLOCK_SIZE
    }

    fn seek_to_block(&mut self, block: u64) {
        self.counter = block as u32;
    }
}
