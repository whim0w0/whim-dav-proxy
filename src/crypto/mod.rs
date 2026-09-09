pub mod aes_ctr;
pub mod aes_gcm;
pub mod aes_gcm_siv;
pub mod chacha20;
pub mod chacha20_poly1305;
pub mod crypto_meta;
pub mod filename;

pub const CYPTO_META_SIZE: usize = 64;

pub const CYPTO_HEADER_SIZE: usize = CYPTO_META_SIZE - 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum EncType {
    AesCtr,

    ChaCha20,

    AesGcm,

    ChaCha20Poly1305,

    AesGcmSiv,
}

impl EncType {
    pub fn from_str(enc_str: &str) -> Option<Self> {
        match enc_str.to_uppercase().as_str() {
            "AESCTR" => Some(EncType::AesCtr),
            "CHACHA20" => Some(EncType::ChaCha20),
            "AESGCM" => Some(EncType::AesGcm),
            "CHACHA20POLY1305" | "CHACHA20-POLY1305" => Some(EncType::ChaCha20Poly1305),
            "AESGCMSIV" | "AES-GCM-SIV" => Some(EncType::AesGcmSiv),
            _ => None,
        }
    }

    pub fn magic_bytes(&self) -> &'static [u8] {
        match self {
            EncType::AesCtr => b"AES--CTR",
            EncType::ChaCha20 => b"CHACHA20",
            EncType::AesGcm => b"AES-GCM1",
            EncType::ChaCha20Poly1305 => b"C20P1305",
            EncType::AesGcmSiv => b"AES-SIV1",
        }
    }

    pub fn from_magic(magic: &str) -> Option<Self> {
        match magic {
            "AES--CTR" => Some(EncType::AesCtr),
            "CHACHA20" => Some(EncType::ChaCha20),
            "AES-GCM1" => Some(EncType::AesGcm),
            "C20P1305" => Some(EncType::ChaCha20Poly1305),
            "AES-SIV1" => Some(EncType::AesGcmSiv),
            _ => None,
        }
    }

    pub fn new_block_cipher(&self, password: &[u8]) -> Box<dyn BlockCipher> {
        match self {
            EncType::AesGcm => AesGcm::new_block_cipher(password),
            EncType::ChaCha20Poly1305 => ChaCha20Poly1305::new_block_cipher(password),
            EncType::AesGcmSiv => AesGcmSiv::new_block_cipher(password),

            EncType::AesCtr | EncType::ChaCha20 => {
                unreachable!("new_block_cipher called for non-block enc_type")
            }
        }
    }

    pub fn new_stream_cipher(&self, password: &[u8]) -> Box<dyn StreamCipher> {
        match self {
            EncType::AesCtr => AesCtr::new_stream_cipher(password),
            EncType::ChaCha20 => ChaCha20::new_stream_cipher(password),

            EncType::AesGcm | EncType::ChaCha20Poly1305 | EncType::AesGcmSiv => {
                unreachable!("new_stream_cipher called for non-stream enc_type")
            }
        }
    }

    pub fn parse_block_header(
        &self,
        password: &[u8],
        header: [u8; CYPTO_HEADER_SIZE],
    ) -> Box<dyn BlockCipher> {
        match self {
            EncType::AesGcm => AesGcm::parse_block_cipher(password, header),
            EncType::ChaCha20Poly1305 => ChaCha20Poly1305::parse_block_cipher(password, header),
            EncType::AesGcmSiv => AesGcmSiv::parse_block_cipher(password, header),

            EncType::AesCtr | EncType::ChaCha20 => {
                unreachable!("parse_block_header called for non-block enc_type")
            }
        }
    }

    pub fn parse_stream_header(
        &self,
        password: &[u8],
        header: [u8; CYPTO_HEADER_SIZE],
    ) -> Box<dyn StreamCipher> {
        match self {
            EncType::AesCtr => AesCtr::parse_stream_cipher(password, header),
            EncType::ChaCha20 => ChaCha20::parse_stream_cipher(password, header),

            EncType::AesGcm | EncType::ChaCha20Poly1305 | EncType::AesGcmSiv => {
                unreachable!("parse_stream_header called for non-stream enc_type")
            }
        }
    }
}

pub trait Cipher: Send {
    fn gen_header(&self) -> [u8; CYPTO_HEADER_SIZE];
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;

    fn plaintext_len_of(&self, cipher_len: u64) -> Option<u64> {
        cipher_len.checked_sub(CYPTO_META_SIZE as u64)
    }

    fn map_plain_to_cipher(&self, plain_start: u64) -> (u64, usize) {
        (CYPTO_META_SIZE as u64 + plain_start, 0)
    }
}

pub trait BlockCipher: Cipher {
    fn new_block_cipher(password: &[u8]) -> Box<dyn BlockCipher>
    where
        Self: Sized;

    fn parse_block_cipher(password: &[u8], header: [u8; CYPTO_HEADER_SIZE]) -> Box<dyn BlockCipher>
    where
        Self: Sized;

    fn frame_size(&self) -> usize;

    fn plain_block_size(&self) -> usize;

    fn seek_to_block(&mut self, block: u64);
}

pub trait StreamCipher: Cipher {
    fn new_stream_cipher(password: &[u8]) -> Box<dyn StreamCipher>
    where
        Self: Sized;

    fn parse_stream_cipher(
        password: &[u8],
        header: [u8; CYPTO_HEADER_SIZE],
    ) -> Box<dyn StreamCipher>
    where
        Self: Sized;
}
pub use crypto_meta::CryptoMeta;
pub use filename::FileNameConverter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Block,
    Stream,
}

impl EncType {
    pub fn kind(&self) -> CipherKind {
        match self {
            EncType::AesGcm | EncType::ChaCha20Poly1305 | EncType::AesGcmSiv => CipherKind::Block,
            EncType::AesCtr | EncType::ChaCha20 => CipherKind::Stream,
        }
    }
}

use aes_ctr::AesCtr;
use aes_gcm::AesGcm;
use aes_gcm_siv::AesGcmSiv;
use chacha20::ChaCha20;
use chacha20_poly1305::ChaCha20Poly1305;
