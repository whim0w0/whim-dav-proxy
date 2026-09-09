use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use futures_util::StreamExt;
use std::sync::Arc;
use tracing::debug;

use crate::config::{BackendConfig, EncryptionConfig};
use crate::crypto::FileNameConverter;
use crate::errors::ProxyError;
use crate::service::proxy::ProxyEngine;

pub struct WebDavHandler {
    pub engine: Arc<ProxyEngine>,

    pub cfg: Arc<BackendConfig>,
}

impl WebDavHandler {
    pub fn new(engine: Arc<ProxyEngine>, cfg: Arc<BackendConfig>) -> Self {
        Self { engine, cfg }
    }

    pub async fn handle(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: axum::body::Body,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        let dav_path: &str = if path.is_empty() { "/" } else { path };

        let dav_path: String = self.strip_upstream_prefix(dav_path);

        match method {
            Method::PUT => self.handle_put(&dav_path, &headers, body).await,
            _ => {
                let bytes: Bytes = collect_body(body).await?;
                match method {
                    Method::GET => self.handle_get(&dav_path, &headers).await,
                    Method::HEAD => self.handle_head(&dav_path, &headers).await,
                    ref m if m.as_str() == "PROPFIND" => {
                        self.handle_propfind(&dav_path, &headers, bytes).await
                    }
                    Method::DELETE => self.handle_delete(&dav_path, &headers).await,
                    ref m if m.as_str() == "MOVE" => {
                        self.handle_move_or_copy(&dav_path, &headers, "MOVE").await
                    }
                    ref m if m.as_str() == "COPY" => {
                        self.handle_move_or_copy(&dav_path, &headers, "COPY").await
                    }
                    _ => self.handle_passthrough(path, method, &headers, bytes).await,
                }
            }
        }
    }

    fn encryption_enabled(&self) -> bool {
        self.cfg
            .encryption
            .as_ref()
            .map_or(false, |e: &EncryptionConfig| e.enable)
    }

    fn strip_upstream_prefix(&self, path: &str) -> String {
        let prefix: String = self.cfg.webdav_host.path_prefix();
        if prefix.is_empty() || prefix == "/" {
            return path.to_string();
        }
        path.strip_prefix(&prefix).unwrap_or(path).to_string()
    }

    fn encrypt_path(&self, path: &str) -> String {
        if !self.encryption_enabled() {
            return path.to_string();
        }
        let enc: &EncryptionConfig = match self.cfg.encryption.as_ref() {
            Some(e) => e,
            None => return path.to_string(),
        };
        if !enc.enc_name {
            return path.to_string();
        }

        let converter: FileNameConverter =
            FileNameConverter::new(&enc.password, &enc.enc_type, enc.enc_suffix.as_deref());
        converter.encrypt_path(path)
    }

    async fn handle_passthrough(
        &self,
        path: &str,
        method: Method,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        let target_url: String = ProxyEngine::upstream_url(&self.cfg, path);
        self.engine
            .proxy_request(method, &target_url, headers, body)
            .await
            .map(|(s, h, b)| (s, h, Body::from(b)))
    }

    async fn handle_get(
        &self,
        dav_path: &str,
        headers: &HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        if !self.encryption_enabled() {
            let target_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);
            debug!(method = "GET", path = dav_path, url = %target_url, "Proxying request");
            return self
                .engine
                .proxy_request(Method::GET, &target_url, headers, Bytes::new())
                .await
                .map(|(s, h, b)| (s, h, Body::from(b)));
        }

        let enc: &EncryptionConfig = self.cfg.encryption.as_ref().unwrap();
        let real_path: String = self.encrypt_path(dav_path);
        let target_url: String = ProxyEngine::upstream_url(&self.cfg, &real_path);

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<Bytes, ProxyError>>();
        let (status, resp_headers) = self
            .engine
            .download_with_decrypt(&target_url, headers, enc, tx)
            .await?;

        let body_stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        let body = Body::from_stream(body_stream);
        Ok((status, resp_headers, body))
    }

    async fn handle_head(
        &self,
        dav_path: &str,
        headers: &HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        if !self.encryption_enabled() {
            let target_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);
            let (status, resp_headers) = self.engine.proxy_head(&target_url, headers).await?;
            return Ok((status, resp_headers, Body::empty()));
        }

        let enc: &EncryptionConfig = self.cfg.encryption.as_ref().unwrap();
        let real_path: String = self.encrypt_path(dav_path);
        let target_url: String = ProxyEngine::upstream_url(&self.cfg, &real_path);
        let (status, resp_headers) = self
            .engine
            .head_with_decrypt(&target_url, headers, enc)
            .await?;
        Ok((status, resp_headers, Body::empty()))
    }

    async fn handle_put(
        &self,
        dav_path: &str,
        headers: &HeaderMap,
        body: axum::body::Body,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        if !self.encryption_enabled() {
            let target_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);
            let bytes: Bytes = collect_body(body).await?;
            return self
                .engine
                .proxy_request(Method::PUT, &target_url, headers, bytes)
                .await
                .map(|(s, h, b)| (s, h, Body::from(b)));
        }

        let enc: &EncryptionConfig = self.cfg.encryption.as_ref().unwrap();
        let real_path: String = self.encrypt_path(dav_path);
        let target_url: String = ProxyEngine::upstream_url(&self.cfg, &real_path);

        let body_stream = body
            .into_data_stream()
            .map(|r| r.map_err(|e| ProxyError::internal(format!("body stream: {}", e))));

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<Bytes, ProxyError>>();
        let (status, resp_headers) = self
            .engine
            .upload_with_encrypt(&target_url, headers, body_stream, enc, tx)
            .await?;

        let resp_stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        Ok((status, resp_headers, Body::from_stream(resp_stream)))
    }

    async fn handle_delete(
        &self,
        dav_path: &str,
        headers: &HeaderMap,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        let enc: Option<&EncryptionConfig> = self.cfg.encryption.as_ref();
        let has_enc_name: bool = enc.map_or(false, |e: &EncryptionConfig| e.enable && e.enc_name);

        if !has_enc_name {
            let target_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);
            return self
                .engine
                .proxy_request(Method::DELETE, &target_url, headers, Bytes::new())
                .await
                .map(|(s, h, b)| (s, h, Body::from(b)));
        }

        let real_path: String = self.encrypt_path(dav_path);
        let target_url: String = ProxyEngine::upstream_url(&self.cfg, &real_path);

        let (status, resp_headers, resp_body) = self
            .engine
            .proxy_request(Method::DELETE, &target_url, headers, Bytes::new())
            .await?;

        if !is_missing_resource(status) {
            return Ok((status, resp_headers, Body::from(resp_body)));
        }

        let plain_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);
        self.engine
            .proxy_request(Method::DELETE, &plain_url, headers, Bytes::new())
            .await
            .map(|(s, h, b)| (s, h, Body::from(b)))
    }

    async fn handle_move_or_copy(
        &self,
        dav_path: &str,
        headers: &HeaderMap,
        method_str: &str,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        let method: Method = Method::from_bytes(method_str.as_bytes()).unwrap_or_else(
            |_: axum::http::method::InvalidMethod| Method::from_bytes(b"MOVE").unwrap(),
        );

        let mut new_headers: HeaderMap = headers.clone();
        if let Some(dest) = headers.get("Destination") {
            if let Ok(dest_str) = dest.to_str() {
                if let Some(dest_path) = self.destination_path(dest_str) {
                    let real_dest: String = self.encrypt_path(&dest_path);
                    let upstream_dest: String =
                        ProxyEngine::upstream_url(&self.cfg, &real_dest);
                    if let Ok(val) = HeaderValue::from_str(&upstream_dest) {
                        new_headers.insert("Destination", val);
                    }
                }
            }
        }

        let real_path: String = self.encrypt_path(dav_path);
        let target_url: String = ProxyEngine::upstream_url(&self.cfg, &real_path);
        debug!(
            method = method_str,
            src = dav_path,
            url = %target_url,
            dest = ?new_headers.get("Destination"),
            "MOVE/COPY forwarding"
        );
        let (status, resp_headers, resp_body) = self
            .engine
            .proxy_request(method.clone(), &target_url, &new_headers, Bytes::new())
            .await?;

        if method_str == "MOVE" && is_missing_resource(status) {
            let plain_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);
            let mut plain_headers: HeaderMap = headers.clone();
            if let Some(dest) = headers.get("Destination") {
                if let Ok(dest_str) = dest.to_str() {
                    if let Some(dest_path) = self.destination_path(dest_str) {
                        let plain_dest: String =
                            ProxyEngine::upstream_url(&self.cfg, &dest_path);
                        if let Ok(val) = HeaderValue::from_str(&plain_dest) {
                            plain_headers.insert("Destination", val);
                        }
                    }
                }
            }
            return self
                .engine
                .proxy_request(method, &plain_url, &plain_headers, Bytes::new())
                .await
                .map(|(s, h, b)| (s, h, Body::from(b)));
        }

        Ok((status, resp_headers, Body::from(resp_body)))
    }

    fn destination_path(&self, dest: &str) -> Option<String> {
        let raw: String = if dest.starts_with("http://") || dest.starts_with("https://") {
            let parsed: url::Url = url::Url::parse(dest).ok()?;
            parsed.path().to_string()
        } else {
            dest.to_string()
        };

        let without_prefix: String = self.strip_upstream_prefix(&raw);
        if without_prefix.is_empty() {
            None
        } else {
            Some(without_prefix)
        }
    }

    async fn handle_propfind(
        &self,
        dav_path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Body), ProxyError> {
        let has_enc_name: bool = self
            .cfg
            .encryption
            .as_ref()
            .map_or(false, |e: &EncryptionConfig| e.enable && e.enc_name);

        let target_url: String = ProxyEngine::upstream_url(&self.cfg, dav_path);

        let method: Method = Method::from_bytes(b"PROPFIND").unwrap_or(Method::GET);
        let (status, mut resp_headers, resp_bytes) = self
            .engine
            .proxy_request(method, &target_url, headers, body)
            .await?;

        let mut resp_body: Vec<u8> = resp_bytes.to_vec();

        if has_enc_name && status == StatusCode::from_u16(207).unwrap_or(StatusCode::OK) {
            if let Some(enc) = self.cfg.encryption.as_ref() {
                resp_body = self.decrypt_propfind_xml(&resp_body, enc);
            }
        }

        resp_body = self.strip_propfind_hrefs(&resp_body);
        resp_headers.remove("content-length");
        resp_headers.remove("transfer-encoding");

        Ok((status, resp_headers, Body::from(resp_body)))
    }

    fn decrypt_propfind_xml(&self, body: &[u8], enc: &EncryptionConfig) -> Vec<u8> {
        let text: &str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return body.to_vec(),
        };

        let converter: FileNameConverter =
            FileNameConverter::new(&enc.password, &enc.enc_type, enc.enc_suffix.as_deref());

        let mut result: String = String::with_capacity(text.len());
        let mut remaining: &str = text;

        while !remaining.is_empty() {
            if let Some(href_start) = remaining.find("<D:href>") {
                result.push_str(&remaining[..href_start + 8]);
                remaining = &remaining[href_start + 8..];

                if let Some(href_end) = remaining.find("</D:href>") {
                    let href: &str = &remaining[..href_end];
                    let decrypted: String = converter.decrypt_path(href);
                    result.push_str(&decrypted);
                    result.push_str("</D:href>");
                    remaining = &remaining[href_end + 9..];
                } else {
                    result.push_str(remaining);
                    remaining = "";
                }
            } else {
                result.push_str(remaining);
                remaining = "";
            }
        }

        result.into_bytes()
    }

    fn strip_propfind_hrefs(&self, body: &[u8]) -> Vec<u8> {
        let prefix: String = self.cfg.webdav_host.path_prefix();
        if prefix.is_empty() || prefix == "/" {
            return body.to_vec();
        }

        let text: &str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return body.to_vec(),
        };

        let pattern: String = format!("{}/", prefix);
        text.replace(&pattern, "/").as_bytes().to_vec()
    }

    pub fn inject_auth(headers: &mut HeaderMap, cfg: &BackendConfig) -> () {
        if let Some(auth) = cfg.webdav_host.basic_auth_header() {
            if let Ok(val) = HeaderValue::from_str(&auth) {
                headers.insert("Authorization", val);
            }
        }
    }
}

fn is_missing_resource(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::GONE
    )
}

async fn collect_body(body: axum::body::Body) -> Result<Bytes, ProxyError> {
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk: Bytes = chunk.map_err(|e| ProxyError::internal(format!("read body: {}", e)))?;
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}
