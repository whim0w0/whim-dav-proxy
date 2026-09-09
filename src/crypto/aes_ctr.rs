use aes::cipher::{KeyIvInit, StreamCipher as _};
use sha2::{Digest, Sha256};

use crate::crypto::{CYPTO_HEADER_SIZE, Cipher, StreamCipher};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub struct AesCtr {
    nonce: [u8; 16],
    cipher: Aes256Ctr,
}

impl AesCtr {
    fn derive_key(password: &[u8]) -> [u8; 32] {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(b"aesctr-key-v1");

        hasher.update(password);
        let result: [u8; 32] = hasher.finalize().into();
        result
    }

    fn derive_iv(password: &[u8]) -> [u8; 16] {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(b"aesctr-iv-v1");

        hasher.update(password);
        let hash: [u8; 32] = hasher.finalize().into();
        let mut iv: [u8; 16] = [0u8; 16];
        iv.copy_from_slice(&hash[..16]);

        iv
    }

    fn boxed_new(password: &[u8]) -> Box<Self> {
        let key: [u8; 32] = Self::derive_key(password);
        let iv: [u8; 16] = Self::derive_iv(password);

        let nonce: [u8; 16] = rand::random();

        let cipher: Aes256Ctr = Aes256Ctr::new(&key.into(), &iv.into());
        Box::new(Self { cipher, nonce })
    }

    fn boxed_parse(password: &[u8], header: [u8; CYPTO_HEADER_SIZE]) -> Box<Self> {
        let key: [u8; 32] = Self::derive_key(password);
        let iv: [u8; 16] = Self::derive_iv(password);

        let cipher: Aes256Ctr = Aes256Ctr::new(&key.into(), &iv.into());
        let mut nonce: [u8; 16] = [0u8; 16];
        nonce.copy_from_slice(&header[0..16]);
        Box::new(Self { nonce, cipher })
    }
}

impl Cipher for AesCtr {
    fn gen_header(&self) -> [u8; CYPTO_HEADER_SIZE] {
        let mut header: [u8; CYPTO_HEADER_SIZE] = [0u8; CYPTO_HEADER_SIZE];
        header[0..16].copy_from_slice(&self.nonce);

        header
    }

    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = data.to_vec();
        self.cipher.apply_keystream(&mut buf);
        buf
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        Self::encrypt(self, data)
    }
}

impl StreamCipher for AesCtr {
    fn new_stream_cipher(password: &[u8]) -> Box<dyn StreamCipher> {
        Self::boxed_new(password)
    }

    fn parse_stream_cipher(
        password: &[u8],
        header: [u8; CYPTO_HEADER_SIZE],
    ) -> Box<dyn StreamCipher> {
        Self::boxed_parse(password, header)
    }
}
