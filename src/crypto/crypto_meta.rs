use crate::crypto::{CYPTO_HEADER_SIZE, CYPTO_META_SIZE};

use super::EncType;

pub struct CryptoMeta {
    pub enc_type: EncType,

    pub append_data: [u8; CYPTO_HEADER_SIZE],
}

impl CryptoMeta {
    pub fn parse_header(data: &[u8]) -> Option<Self> {
        if data.len() < CYPTO_META_SIZE {
            return None;
        }

        let magic_str: &str = std::str::from_utf8(&data[..8]).ok()?;

        let op_enc_type: Option<EncType> = EncType::from_magic(magic_str);
        if op_enc_type.is_none() {
            return None;
        }
        let enc_type = op_enc_type.unwrap();
        let mut append_data: [u8; CYPTO_HEADER_SIZE] = [0u8; CYPTO_HEADER_SIZE];
        append_data.copy_from_slice(&data[8..CYPTO_META_SIZE]);
        Some(CryptoMeta {
            enc_type: enc_type,
            append_data,
        })
    }

    pub fn gen_header(&self) -> [u8; CYPTO_META_SIZE] {
        let mut header = [0u8; CYPTO_META_SIZE];
        header[0..8].copy_from_slice(&self.enc_type.magic_bytes());

        header[8..64].copy_from_slice(&self.append_data);
        return header;
    }
}
