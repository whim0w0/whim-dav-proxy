use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::mpsc::UnboundedSender;

use crate::crypto::{BlockCipher, CYPTO_META_SIZE, CryptoMeta, EncType, StreamCipher};
use crate::errors::ProxyError;

pub(super) enum CipherBox {
    Block(Box<dyn BlockCipher>),
    Stream(Box<dyn StreamCipher>),
}

impl CipherBox {
    pub(super) fn from_meta(meta: &CryptoMeta, password: &[u8]) -> Self {
        match meta.enc_type.kind() {
            crate::crypto::CipherKind::Block => {
                CipherBox::Block(meta.enc_type.parse_block_header(password, meta.append_data))
            }
            crate::crypto::CipherKind::Stream => CipherBox::Stream(
                meta.enc_type
                    .parse_stream_header(password, meta.append_data),
            ),
        }
    }

    pub(super) fn skip_header(&mut self) {
        let zeros: Vec<u8> = vec![0u8; CYPTO_META_SIZE];
        match self {
            CipherBox::Block(c) => {
                c.decrypt(&zeros);
            }
            CipherBox::Stream(c) => {
                c.decrypt(&zeros);
            }
        }
    }

    pub(super) fn seek_to_plain(&mut self, start_plain: u64) {
        if let CipherBox::Block(c) = self {
            let bs: u64 = c.plain_block_size() as u64;
            c.seek_to_block(start_plain / bs + 1);
        }
    }

    pub(super) fn reparse(&self, meta: &CryptoMeta, password: &[u8]) -> Self {
        match self {
            CipherBox::Block(_) => {
                CipherBox::Block(meta.enc_type.parse_block_header(password, meta.append_data))
            }
            CipherBox::Stream(_) => CipherBox::Stream(
                meta.enc_type
                    .parse_stream_header(password, meta.append_data),
            ),
        }
    }

    pub(super) fn plaintext_len_of(&self, cipher_len: u64) -> Option<u64> {
        match self {
            CipherBox::Block(c) => c.plaintext_len_of(cipher_len),
            CipherBox::Stream(c) => c.plaintext_len_of(cipher_len),
        }
    }

    pub(super) fn map_plain_to_cipher(&self, start_plain: u64) -> (u64, usize) {
        match self {
            CipherBox::Block(c) => c.map_plain_to_cipher(start_plain),
            CipherBox::Stream(c) => c.map_plain_to_cipher(start_plain),
        }
    }

    pub(super) fn cipher_end_for(&self, start_plain: u64, want: u64) -> u64 {
        match self {
            CipherBox::Block(c) => {
                let bs: u64 = c.plain_block_size() as u64;
                let fs: u64 = c.frame_size() as u64;
                let end: u64 = start_plain + want.saturating_sub(1);

                let last_block: u64 = end / bs;

                CYPTO_META_SIZE as u64 + (last_block + 1) * fs - 1
            }
            CipherBox::Stream(_) => CYPTO_META_SIZE as u64 + start_plain + want - 1,
        }
    }

    pub(super) fn new_for_upload(enc_type: EncType, password: &[u8]) -> (Self, Bytes) {
        let mut boxed: CipherBox = CipherBox::from_type_new(enc_type, password);

        let header: [u8; crate::crypto::CYPTO_HEADER_SIZE] = match &boxed {
            CipherBox::Block(c) => c.gen_header(),
            CipherBox::Stream(c) => c.gen_header(),
        };
        let meta: CryptoMeta = CryptoMeta {
            enc_type,
            append_data: header,
        };
        let meta_header: Bytes = Bytes::copy_from_slice(&meta.gen_header());

        boxed.skip_header();
        (boxed, meta_header)
    }

    fn from_type_new(enc_type: EncType, password: &[u8]) -> Self {
        match enc_type.kind() {
            crate::crypto::CipherKind::Block => {
                CipherBox::Block(enc_type.new_block_cipher(password))
            }
            crate::crypto::CipherKind::Stream => {
                CipherBox::Stream(enc_type.new_stream_cipher(password))
            }
        }
    }
}

fn strip_prefix(data: Bytes, cipher_prefix: &mut usize) -> Option<Bytes> {
    if *cipher_prefix == 0 {
        return Some(data);
    }
    if data.len() <= *cipher_prefix {
        *cipher_prefix -= data.len();
        return None;
    }
    let d: Bytes = data.slice(*cipher_prefix..);
    *cipher_prefix = 0;
    Some(d)
}

fn emit_plain(
    plain: Vec<u8>,
    skip_plain_prefix: usize,
    want: Option<u64>,
    skipped: &mut u64,
    sent: &mut u64,
    tx: &UnboundedSender<Result<Bytes, ProxyError>>,
) -> bool {
    let mut p: Vec<u8> = plain;

    if *skipped < skip_plain_prefix as u64 {
        let n: usize = ((skip_plain_prefix as u64) - *skipped).min(p.len() as u64) as usize;
        p.drain(..n);
        *skipped += n as u64;
    }

    if let Some(w) = want {
        let remain: u64 = w.saturating_sub(*sent);
        if p.len() as u64 > remain {
            p.truncate(remain as usize);
        }
    }
    *sent += p.len() as u64;
    if !p.is_empty() {
        if tx.send(Ok(Bytes::from(p))).is_err() {
            return false;
        }
    }
    if let Some(w) = want {
        if *sent >= w {
            return false;
        }
    }
    true
}

pub(super) struct BlockEngine;

impl BlockEngine {
    fn spawn_block_decrypt(
        &self,
        response: reqwest::Response,
        mut cipher: Box<dyn BlockCipher>,
        skip_cipher_prefix: usize,
        skip_plain_prefix: usize,
        want: Option<u64>,
        tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) {
        let frame: usize = cipher.frame_size();
        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            let mut cipher_prefix: usize = skip_cipher_prefix;
            let mut buf: Vec<u8> = Vec::new();
            let mut skipped: u64 = 0;

            let mut sent: u64 = 0;

            while let Some(chunk) = stream.next().await {
                let data: Bytes = match chunk {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = tx.send(Err(ProxyError::proxy(format!("stream read: {}", e))));
                        return;
                    }
                };

                let Some(data) = strip_prefix(data, &mut cipher_prefix) else {
                    continue;
                };

                buf.extend_from_slice(&data);
                while buf.len() >= frame {
                    let plain: Vec<u8> = cipher.decrypt(&buf[..frame]);
                    buf.drain(..frame);

                    if plain.is_empty() {
                        let _ = tx.send(Err(ProxyError::proxy(
                            "GCM auth failed: encrypted data corrupted or wrong password",
                        )));
                        return;
                    }
                    if !emit_plain(plain, skip_plain_prefix, want, &mut skipped, &mut sent, &tx) {
                        return;
                    }
                }
            }

            if !buf.is_empty() {
                let plain: Vec<u8> = cipher.decrypt(&buf);
                if plain.is_empty() {
                    let _ = tx.send(Err(ProxyError::proxy(
                        "GCM auth failed: final block corrupted or wrong password",
                    )));
                    return;
                }
                emit_plain(plain, skip_plain_prefix, want, &mut skipped, &mut sent, &tx);
            }
        });
    }

    fn spawn_block_encrypt<S>(
        &self,
        body_stream: S,
        mut cipher: Box<dyn BlockCipher>,
        meta_header: Bytes,
        body_tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) where
        S: futures_util::Stream<Item = Result<Bytes, ProxyError>> + Send + 'static,
    {
        let block: usize = cipher.plain_block_size();
        tokio::spawn(async move {
            if body_tx.send(Ok(meta_header)).is_err() {
                return;
            }
            let mut plain_buf: Vec<u8> = Vec::with_capacity(block);
            let mut stream = Box::pin(body_stream);

            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(data) => {
                        plain_buf.extend_from_slice(&data);

                        while plain_buf.len() >= block {
                            let enc: Vec<u8> = cipher.encrypt(&plain_buf[..block]);
                            plain_buf.drain(..block);
                            if body_tx.send(Ok(Bytes::from(enc))).is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = body_tx.send(Err(e));
                        return;
                    }
                }
            }

            if !plain_buf.is_empty() {
                let enc: Vec<u8> = cipher.encrypt(&plain_buf);
                let _ = body_tx.send(Ok(Bytes::from(enc)));
            }
        });
    }
}

pub(super) struct StreamEngine;

impl StreamEngine {
    fn spawn_stream_decrypt(
        &self,
        response: reqwest::Response,
        mut cipher: Box<dyn StreamCipher>,
        skip_cipher_prefix: usize,
        skip_plain_prefix: usize,
        want: Option<u64>,
        tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) {
        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            let mut cipher_prefix: usize = skip_cipher_prefix;
            let mut skipped: u64 = 0;

            let mut sent: u64 = 0;

            while let Some(chunk) = stream.next().await {
                let data: Bytes = match chunk {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = tx.send(Err(ProxyError::proxy(format!("stream read: {}", e))));
                        return;
                    }
                };

                let Some(data) = strip_prefix(data, &mut cipher_prefix) else {
                    continue;
                };

                let plain: Vec<u8> = cipher.decrypt(&data);
                if !emit_plain(plain, skip_plain_prefix, want, &mut skipped, &mut sent, &tx) {
                    return;
                }
            }
        });
    }

    fn spawn_stream_range_decrypt(
        &self,
        response: reqwest::Response,
        mut cipher: Box<dyn StreamCipher>,
        start_plain: u64,
        skip_plain_prefix: usize,
        want: Option<u64>,
        tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) {
        let mut remaining: u64 = CYPTO_META_SIZE as u64 + start_plain;
        const KEYSTREAM_CHUNK: u64 = 1024 * 1024;
        while remaining > 0 {
            let n: usize = remaining.min(KEYSTREAM_CHUNK) as usize;
            cipher.decrypt(&vec![0u8; n]);
            remaining -= n as u64;
        }
        self.spawn_stream_decrypt(response, cipher, 0, skip_plain_prefix, want, tx)
    }

    fn spawn_stream_encrypt<S>(
        &self,
        body_stream: S,
        mut cipher: Box<dyn StreamCipher>,
        meta_header: Bytes,
        body_tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) where
        S: futures_util::Stream<Item = Result<Bytes, ProxyError>> + Send + 'static,
    {
        tokio::spawn(async move {
            if body_tx.send(Ok(meta_header)).is_err() {
                return;
            }
            let mut stream = Box::pin(body_stream);

            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(data) => {
                        let enc: Vec<u8> = cipher.encrypt(&data);
                        if body_tx.send(Ok(Bytes::from(enc))).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = body_tx.send(Err(e));
                        return;
                    }
                }
            }
        });
    }
}

pub(super) enum CipherEngine {
    Block(BlockEngine),
    Stream(StreamEngine),
}

impl CipherEngine {
    pub(super) fn for_type(enc_type: EncType) -> Self {
        match enc_type.kind() {
            crate::crypto::CipherKind::Block => CipherEngine::Block(BlockEngine),
            crate::crypto::CipherKind::Stream => CipherEngine::Stream(StreamEngine),
        }
    }

    pub(super) fn spawn_decrypt(
        &self,
        response: reqwest::Response,
        cipher: CipherBox,
        skip_cipher_prefix: usize,
        skip_plain_prefix: usize,
        want: Option<u64>,
        tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) {
        debug_assert!(
            matches!(
                (self, &cipher),
                (CipherEngine::Block(_), CipherBox::Block(_))
                    | (CipherEngine::Stream(_), CipherBox::Stream(_))
            ),
            "CipherEngine 与 CipherBox 算法族不一致"
        );
        match (self, cipher) {
            (CipherEngine::Block(e), CipherBox::Block(c)) => {
                e.spawn_block_decrypt(response, c, skip_cipher_prefix, skip_plain_prefix, want, tx)
            }
            (CipherEngine::Stream(e), CipherBox::Stream(c)) => {
                e.spawn_stream_decrypt(response, c, skip_cipher_prefix, skip_plain_prefix, want, tx)
            }
            (CipherEngine::Block(_), CipherBox::Stream(_))
            | (CipherEngine::Stream(_), CipherBox::Block(_)) => {
                unreachable!("算法族不匹配（debug_assert 应已拦截）")
            }
        }
    }

    pub(super) fn spawn_range_decrypt(
        &self,
        response: reqwest::Response,
        cipher: CipherBox,
        start_plain: u64,
        skip_plain_prefix: usize,
        want: Option<u64>,
        tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) {
        debug_assert!(
            matches!(
                (self, &cipher),
                (CipherEngine::Block(_), CipherBox::Block(_))
                    | (CipherEngine::Stream(_), CipherBox::Stream(_))
            ),
            "CipherEngine 与 CipherBox 算法族不一致"
        );
        match (self, cipher) {
            (CipherEngine::Block(e), CipherBox::Block(c)) => {
                e.spawn_block_decrypt(response, c, 0, skip_plain_prefix, want, tx)
            }
            (CipherEngine::Stream(e), CipherBox::Stream(c)) => {
                e.spawn_stream_range_decrypt(response, c, start_plain, skip_plain_prefix, want, tx)
            }

            (CipherEngine::Block(_), CipherBox::Stream(_))
            | (CipherEngine::Stream(_), CipherBox::Block(_)) => {
                unreachable!("算法族不匹配（debug_assert 应已拦截）")
            }
        }
    }

    pub(super) fn spawn_encrypt<S>(
        &self,
        body_stream: S,
        cipher: CipherBox,
        meta_header: Bytes,
        body_tx: UnboundedSender<Result<Bytes, ProxyError>>,
    ) where
        S: futures_util::Stream<Item = Result<Bytes, ProxyError>> + Send + 'static,
    {
        debug_assert!(
            matches!(
                (self, &cipher),
                (CipherEngine::Block(_), CipherBox::Block(_))
                    | (CipherEngine::Stream(_), CipherBox::Stream(_))
            ),
            "CipherEngine 与 CipherBox 算法族不一致"
        );
        match (self, cipher) {
            (CipherEngine::Block(e), CipherBox::Block(c)) => {
                e.spawn_block_encrypt(body_stream, c, meta_header, body_tx)
            }
            (CipherEngine::Stream(e), CipherBox::Stream(c)) => {
                e.spawn_stream_encrypt(body_stream, c, meta_header, body_tx)
            }

            (CipherEngine::Block(_), CipherBox::Stream(_))
            | (CipherEngine::Stream(_), CipherBox::Block(_)) => {
                unreachable!("算法族不匹配（debug_assert 应已拦截）")
            }
        }
    }
}
