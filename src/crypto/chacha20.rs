use chacha20::cipher::{KeyIvInit, StreamCipher as _};
use sha2::{Digest, Sha256};

use crate::crypto::{CYPTO_HEADER_SIZE, Cipher, StreamCipher};

type ChaCha20Cipher = chacha20::ChaCha20;

pub struct ChaCha20 {
    nonce: [u8; 12],
    cipher: ChaCha20Cipher,
}

impl ChaCha20 {
    fn derive_key(password: &[u8]) -> [u8; 32] {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(b"chacha20-key-v1");

        hasher.update(password);
        let result: [u8; 32] = hasher.finalize().into();
        result
    }

    fn boxed_new(password: &[u8]) -> Box<Self> {
        let key: [u8; 32] = Self::derive_key(password);

        let nonce: [u8; 12] = rand::random();

        let cipher: ChaCha20Cipher = ChaCha20Cipher::new(&key.into(), &nonce.into());
        Box::new(Self { cipher, nonce })
    }

    fn boxed_parse(password: &[u8], header: [u8; CYPTO_HEADER_SIZE]) -> Box<Self> {
        let key: [u8; 32] = Self::derive_key(password);
        let mut nonce: [u8; 12] = [0u8; 12];
        nonce.copy_from_slice(&header[0..12]);
        let cipher: ChaCha20Cipher = ChaCha20Cipher::new(&key.into(), &nonce.into());
        Box::new(Self { cipher, nonce })
    }
}

impl Cipher for ChaCha20 {
    fn gen_header(&self) -> [u8; CYPTO_HEADER_SIZE] {
        let mut header: [u8; CYPTO_HEADER_SIZE] = [0u8; CYPTO_HEADER_SIZE];
        header[0..12].copy_from_slice(&self.nonce);

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

impl StreamCipher for ChaCha20 {
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
