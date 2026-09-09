use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::header::{HeaderName, RANGE};
use std::time::Duration;
use tracing::debug;

use crate::backoff::{self, CircuitBreaker};
use crate::config::EncryptionConfig;
use crate::crypto::{CYPTO_META_SIZE, CryptoMeta, EncType};
use crate::errors::ProxyError;
use crate::service::cipher_engine::{CipherBox, CipherEngine};

pub struct ProxyEngine {
    pub client: reqwest::Client,

    pub circuit_breaker: CircuitBreaker,

    pub max_retries: usize,
}

impl ProxyEngine {
    pub fn new(cfg: &crate::config::BackendConfig) -> Result<Self, ProxyError> {
        let insecure: bool = cfg.webdav_host.insecure_skip_verify;

        let client: reqwest::Client = backoff::build_http_client(insecure)
            .map_err(|e: reqwest::Error| ProxyError::internal(format!("http client: {}", e)))?;

        let default_stream: crate::config::StreamConfig = crate::config::StreamConfig::default();
        let stream: &crate::config::StreamConfig = &default_stream;

        let cb: CircuitBreaker = CircuitBreaker::new(
            stream.circuit_breaker_threshold,
            Duration::from_secs(stream.circuit_breaker_cooldown_secs),
        );

        Ok(Self {
            client,
            circuit_breaker: cb,
            max_retries: stream.retry_max_attempts,
        })
    }

    pub fn upstream_url(cfg: &crate::config::BackendConfig, path: &str) -> String {
        let base: &str = cfg.webdav_host.url.trim_end_matches('/');
        if path.starts_with('/') {
            format!("{}{}", base, path)
        } else {
            format!("{}/{}", base, path)
        }
    }

    pub async fn proxy_request(
        &self,
        method: Method,
        target_url: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes), ProxyError> {
        if !self.circuit_breaker.allow() {
            return Err(ProxyError::bad_gateway("circuit open"));
        }

        let req_headers: HeaderMap = convert_headers(headers);
        let target: String = target_url.to_string();
        let m: Method = method.clone();

        let response: reqwest::Response = backoff::retry(self.max_retries, || {
            let req: reqwest::RequestBuilder = self
                .client
                .request(m.clone(), &target)
                .headers(req_headers.clone());
            let b: Bytes = body.clone();

            async move {
                if !b.is_empty() {
                    req.body(b).send().await
                } else {
                    req.send().await
                }
            }
        })
        .await
        .map_err(|e: reqwest::Error| {
            self.circuit_breaker.record_failure();
            ProxyError::proxy(format!("proxy request failed: {}", e))
        })?;

        let status: StatusCode = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        debug!(method = %method, url = %target_url, status = %status, "Upstream response");

        if status.is_server_error() {
            self.circuit_breaker.record_failure();
        } else {
            self.circuit_breaker.record_success();
        }

        let resp_headers: HeaderMap = response.headers().clone();
        let resp_body: Bytes = response
            .bytes()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("read response: {}", e)))?;

        let resp_headers: HeaderMap = strip_content_length(resp_headers);
        Ok((status, resp_headers, resp_body))
    }

    async fn probe_header_with_len(
        &self,
        target_url: &str,
        headers: &HeaderMap,
    ) -> Result<(Option<CryptoMeta>, Option<u64>, Option<HeaderValue>), ProxyError> {
        let mut h: HeaderMap = headers.clone();

        strip_conditional_headers(&mut h);

        h.insert(RANGE, HeaderValue::from_static("bytes=0-63"));

        h.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("identity"),
        );

        let target: String = target_url.to_string();
        let hdrs: HeaderMap = convert_headers(&h);

        let response: reqwest::Response = self
            .client
            .get(&target)
            .headers(hdrs)
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("header probe: {}", e)))?;

        let cipher_len: Option<u64> = response
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit('/').next())
            .and_then(|s| s.trim().parse().ok());
        let content_type: Option<HeaderValue> = response.headers().get("content-type").cloned();

        let data: Bytes = response
            .bytes()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("header probe read: {}", e)))?;

        if data.len() >= 64 {
            if let Some(meta) = CryptoMeta::parse_header(&data[..64]) {
                return Ok((Some(meta), cipher_len, content_type));
            }
        }

        Ok((None, None, None))
    }

    pub async fn download_without_decrypt(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        tx: tokio::sync::mpsc::UnboundedSender<Result<bytes::Bytes, ProxyError>>,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        let req_headers: HeaderMap = convert_headers(headers);
        let response: reqwest::Response = self
            .client
            .get(target_url)
            .headers(req_headers)
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("download: {}", e)))?;

        let status: StatusCode = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            self.circuit_breaker.record_failure();
        } else {
            self.circuit_breaker.record_success();
        }
        let resp_headers: HeaderMap = strip_content_length(response.headers().clone());

        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(data) => {
                        if tx.send(Ok(data)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(ProxyError::proxy(format!("stream read: {}", e))));
                        break;
                    }
                }
            }
        });

        Ok((status, resp_headers))
    }

    pub async fn download_with_decrypt(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        enc: &EncryptionConfig,
        tx: tokio::sync::mpsc::UnboundedSender<Result<bytes::Bytes, ProxyError>>,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        let op_config_enc_type: Option<EncType> = EncType::from_str(&enc.enc_type);
        if op_config_enc_type.is_none() {
            return self.download_without_decrypt(target_url, headers, tx).await;
        }

        let config_enc_type = op_config_enc_type.unwrap();
        let password: &[u8] = enc.password.as_bytes();

        let (op_meta, cipher_len, _content_type): (
            Option<CryptoMeta>,
            Option<u64>,
            Option<HeaderValue>,
        ) = self.probe_header_with_len(target_url, headers).await?;
        if op_meta.is_none() {
            return self.download_without_decrypt(target_url, headers, tx).await;
        }

        let meta = op_meta.unwrap();
        let enc_type: EncType = meta.enc_type;

        if config_enc_type != enc_type {
            return Err(ProxyError::internal("加密类型不匹配"));
        }
        tracing::info!("enc_type: {:?}", enc_type);

        let engine: CipherEngine = CipherEngine::for_type(meta.enc_type);

        if has_range(headers) {
            return self
                .download_decrypt_range(
                    target_url, headers, &meta, password, cipher_len, &engine, tx,
                )
                .await;
        }

        self.download_decrypt_flow(
            target_url, headers, &meta, password, cipher_len, &engine, tx,
        )
        .await
    }

    pub async fn upload_with_encrypt(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        body_stream: impl futures_util::Stream<Item = Result<Bytes, ProxyError>> + Send + 'static,
        enc: &EncryptionConfig,
        tx: tokio::sync::mpsc::UnboundedSender<Result<Bytes, ProxyError>>,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        if !self.circuit_breaker.allow() {
            return Err(ProxyError::bad_gateway("circuit open"));
        }

        let enc_type: EncType = match EncType::from_str(&enc.enc_type) {
            Some(t) => t,
            None => {
                return Err(ProxyError::internal(format!(
                    "unknown enc_type: {}",
                    enc.enc_type
                )));
            }
        };
        let password: Vec<u8> = enc.password.as_bytes().to_vec();

        let (cipher, meta_header): (CipherBox, Bytes) =
            CipherBox::new_for_upload(enc_type, &password);

        let target: String = target_url.to_string();
        let req_headers: HeaderMap = convert_headers(headers);

        let (body_tx, body_rx) =
            tokio::sync::mpsc::unbounded_channel::<Result<Bytes, ProxyError>>();

        let engine: &CipherEngine = &CipherEngine::for_type(enc_type);
        engine.spawn_encrypt(body_stream, cipher, meta_header, body_tx);

        let req_body_stream = futures_util::stream::unfold(body_rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        let req_body: reqwest::Body = reqwest::Body::wrap_stream(req_body_stream);

        let response: reqwest::Response = self
            .client
            .put(&target)
            .headers(req_headers)
            .body(req_body)
            .send()
            .await
            .map_err(|e: reqwest::Error| {
                self.circuit_breaker.record_failure();
                ProxyError::proxy(format!("upload: {}", e))
            })?;

        let status: StatusCode = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let resp_headers: HeaderMap = strip_content_length(response.headers().clone());

        if status.is_server_error() {
            self.circuit_breaker.record_failure();
        } else {
            self.circuit_breaker.record_success();
        }

        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(data) => {
                        if tx.send(Ok(data)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(ProxyError::proxy(format!("upload response: {}", e))));
                        break;
                    }
                }
            }
        });

        Ok((status, resp_headers))
    }

    async fn download_decrypt_flow(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        meta: &CryptoMeta,
        password: &[u8],
        known_cipher_len: Option<u64>,
        engine: &CipherEngine,
        tx: tokio::sync::mpsc::UnboundedSender<Result<bytes::Bytes, ProxyError>>,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        let mut cipher: CipherBox = CipherBox::from_meta(meta, password);

        let plain_len: Option<u64> = match known_cipher_len {
            Some(cl) => cipher.plaintext_len_of(cl),
            None => match self.fetch_cipher_len(target_url, headers).await? {
                Some((cl, _)) => cipher.plaintext_len_of(cl),
                None => None,
            },
        };

        let mut get_headers: HeaderMap = headers.clone();
        strip_conditional_headers(&mut get_headers);

        get_headers.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("identity"),
        );

        get_headers.remove("range");
        get_headers.remove("if-range");

        let req_headers: HeaderMap = convert_headers(&get_headers);
        let response: reqwest::Response = self
            .client
            .get(target_url)
            .headers(req_headers)
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("download: {}", e)))?;

        let status: StatusCode = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            self.circuit_breaker.record_failure();
        } else {
            self.circuit_breaker.record_success();
        }

        let mut resp_headers: HeaderMap = strip_content_length(response.headers().clone());
        if let Some(len) = plain_len {
            if let Ok(v) = HeaderValue::from_str(&len.to_string()) {
                resp_headers.insert("content-length", v);
            }
            resp_headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
        }

        cipher.skip_header();

        engine.spawn_decrypt(response, cipher, CYPTO_META_SIZE, 0, None, tx);

        Ok((status, resp_headers))
    }

    async fn download_decrypt_range(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        meta: &CryptoMeta,
        password: &[u8],
        known_cipher_len: Option<u64>,
        engine: &CipherEngine,
        tx: tokio::sync::mpsc::UnboundedSender<Result<bytes::Bytes, ProxyError>>,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        let req: RangeReq = match parse_range(headers) {
            Some(r) => r,
            None => {
                return self
                    .download_decrypt_flow(
                        target_url,
                        headers,
                        meta,
                        password,
                        known_cipher_len,
                        engine,
                        tx,
                    )
                    .await;
            }
        };

        let cipher_len: u64 = match known_cipher_len {
            Some(cl) => cl,
            None => match self.fetch_cipher_len(target_url, headers).await? {
                Some((l, _up_headers)) => l,
                None => {
                    return self
                        .download_decrypt_flow(
                            target_url, headers, meta, password, None, engine, tx,
                        )
                        .await;
                }
            },
        };

        let mut cipher: CipherBox = CipherBox::from_meta(meta, password);
        let file_len: u64 = match cipher.plaintext_len_of(cipher_len) {
            Some(l) => l,
            None => {
                return self
                    .download_decrypt_flow(
                        target_url,
                        headers,
                        meta,
                        password,
                        Some(cipher_len),
                        engine,
                        tx,
                    )
                    .await;
            }
        };

        let (start, end): (u64, u64) = match resolve_range(req, file_len) {
            Some(r) => r,
            None => {
                drop(tx);

                let mut h: HeaderMap = HeaderMap::new();
                if let Ok(v) = HeaderValue::from_str(&format!("bytes */{}", file_len)) {
                    h.insert("content-range", v);
                }
                return Ok((StatusCode::RANGE_NOT_SATISFIABLE, h));
            }
        };
        let want: u64 = end - start + 1;

        let (cipher_off, skip_plain): (u64, usize) = cipher.map_plain_to_cipher(start);
        cipher.seek_to_plain(start);

        let cipher_end: u64 = cipher.cipher_end_for(start, want).min(cipher_len - 1);
        let mut h: HeaderMap = headers.clone();
        strip_conditional_headers(&mut h);
        h.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("identity"),
        );
        if let Ok(v) = HeaderValue::from_str(&format!("bytes={}-{}", cipher_off, cipher_end)) {
            h.insert(RANGE, v);
        }
        let response: reqwest::Response = self
            .client
            .get(target_url)
            .headers(convert_headers(&h))
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("range download: {}", e)))?;

        let status: StatusCode = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            self.circuit_breaker.record_failure();
        } else {
            self.circuit_breaker.record_success();
        }

        let up_content_type: Option<HeaderValue> = response.headers().get("content-type").cloned();

        match status {
            StatusCode::PARTIAL_CONTENT => {
                engine.spawn_range_decrypt(response, cipher, start, skip_plain, Some(want), tx);
            }

            s if s.is_success() => {
                let mut c2: CipherBox = cipher.reparse(meta, password);
                c2.skip_header();
                engine.spawn_decrypt(
                    response,
                    c2,
                    CYPTO_META_SIZE,
                    start as usize,
                    Some(want),
                    tx,
                );
            }

            _ => {
                drop(tx);
                return Ok((status, strip_content_length(response.headers().clone())));
            }
        }

        let mut resp_headers: HeaderMap = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, file_len)) {
            resp_headers.insert("content-range", v);
        }
        if let Ok(v) = HeaderValue::from_str(&want.to_string()) {
            resp_headers.insert("content-length", v);
        }
        resp_headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
        if let Some(ct) = up_content_type {
            resp_headers.insert("content-type", ct);
        }
        Ok((StatusCode::PARTIAL_CONTENT, resp_headers))
    }

    async fn fetch_cipher_len(
        &self,
        target_url: &str,
        headers: &HeaderMap,
    ) -> Result<Option<(u64, HeaderMap)>, ProxyError> {
        let mut h: HeaderMap = headers.clone();
        strip_conditional_headers(&mut h);
        h.remove("range");
        h.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("identity"),
        );
        let response: reqwest::Response = self
            .client
            .head(target_url)
            .headers(convert_headers(&h))
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("head probe: {}", e)))?;
        if response.status().is_success() {
            let len: Option<u64> = response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok());
            if let Some(l) = len {
                return Ok(Some((l, response.headers().clone())));
            }
        }

        let mut h2: HeaderMap = headers.clone();
        strip_conditional_headers(&mut h2);
        h2.remove("range");
        h2.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("identity"),
        );
        let mut hdrs: HeaderMap = convert_headers(&h2);
        hdrs.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
        let resp2: reqwest::Response = self
            .client
            .get(target_url)
            .headers(hdrs)
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("length probe: {}", e)))?;

        let cr: Option<u64> = resp2
            .headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit('/').next())
            .and_then(|s| s.trim().parse().ok());
        match cr {
            Some(l) => Ok(Some((l, resp2.headers().clone()))),
            None => Ok(None),
        }
    }

    pub async fn proxy_head(
        &self,
        target_url: &str,
        headers: &HeaderMap,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        let mut h: HeaderMap = headers.clone();
        strip_conditional_headers(&mut h);
        h.remove("range");
        let response: reqwest::Response = self
            .client
            .head(target_url)
            .headers(convert_headers(&h))
            .send()
            .await
            .map_err(|e: reqwest::Error| ProxyError::proxy(format!("head: {}", e)))?;
        let status: StatusCode = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Ok((status, response.headers().clone()))
    }

    pub async fn head_with_decrypt(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        enc: &EncryptionConfig,
    ) -> Result<(StatusCode, HeaderMap), ProxyError> {
        let op_config_enc_type: Option<EncType> = EncType::from_str(&enc.enc_type);
        if op_config_enc_type.is_none() {
            return self.proxy_head(target_url, headers).await;
        }
        let config_enc_type = op_config_enc_type.unwrap();
        let password: &[u8] = enc.password.as_bytes();

        let (op_meta, probe_len, probe_ct): (Option<CryptoMeta>, Option<u64>, Option<HeaderValue>) =
            self.probe_header_with_len(target_url, headers).await?;
        if op_meta.is_none() {
            return self.proxy_head(target_url, headers).await;
        }
        let meta = op_meta.unwrap();
        if meta.enc_type != config_enc_type {
            return Err(ProxyError::internal("加密类型不匹配"));
        }

        let (cipher_len, ct): (u64, Option<HeaderValue>) = match probe_len {
            Some(cl) => (cl, probe_ct),
            None => match self.fetch_cipher_len(target_url, headers).await? {
                Some((l, h)) => (l, h.get("content-type").cloned()),
                None => return self.proxy_head(target_url, headers).await,
            },
        };

        let cipher: CipherBox = CipherBox::from_meta(&meta, password);
        let file_len: u64 = match cipher.plaintext_len_of(cipher_len) {
            Some(l) => l,
            None => return self.proxy_head(target_url, headers).await,
        };

        let mut resp_headers: HeaderMap = HeaderMap::new();
        if let Some(ct) = ct {
            resp_headers.insert("content-type", ct);
        }
        if let Ok(v) = HeaderValue::from_str(&file_len.to_string()) {
            resp_headers.insert("content-length", v);
        }
        resp_headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
        Ok((StatusCode::OK, resp_headers))
    }
}

fn convert_headers(src: &HeaderMap) -> HeaderMap {
    let mut dst: HeaderMap = HeaderMap::new();
    for (k, v) in src.iter() {
        let name: &str = k.as_str();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("trailer")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("host")
        {
            continue;
        }
        dst.insert(k.clone(), v.clone());
    }
    dst
}

fn strip_content_length(mut headers: HeaderMap) -> HeaderMap {
    headers.remove("content-length");
    headers.remove("transfer-encoding");
    headers
}

fn strip_conditional_headers(headers: &mut HeaderMap) {
    for name in [
        "if-none-match",
        "if-modified-since",
        "if-match",
        "if-unmodified-since",
        "if-range",
    ] {
        headers.remove(name);
    }
}

fn has_range(headers: &HeaderMap) -> bool {
    headers.contains_key("range") || headers.contains_key("if-range")
}

enum RangeReq {
    From(u64, Option<u64>),

    Suffix(u64),
}

fn parse_range(headers: &HeaderMap) -> Option<RangeReq> {
    let v: &str = headers.get("range")?.to_str().ok()?;
    let spec: &str = v.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (s, e) = spec.split_once('-')?;
    if s.is_empty() {
        let n: u64 = e.parse().ok()?;
        Some(RangeReq::Suffix(n))
    } else {
        let start: u64 = s.parse().ok()?;
        let end: Option<u64> = if e.is_empty() {
            None
        } else {
            Some(e.parse().ok()?)
        };
        Some(RangeReq::From(start, end))
    }
}

fn resolve_range(req: RangeReq, file_len: u64) -> Option<(u64, u64)> {
    let (start, end): (u64, u64) = match req {
        RangeReq::Suffix(n) => {
            if n == 0 {
                return None;
            }
            (file_len.saturating_sub(n), file_len - 1)
        }
        RangeReq::From(start, end) => {
            if start >= file_len {
                return None;
            }
            (start, end.unwrap_or(file_len - 1).min(file_len - 1))
        }
    };
    if end < start {
        return None;
    }
    Some((start, end))
}
