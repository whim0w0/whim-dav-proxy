use std::fmt;

#[derive(Debug)]
pub enum ProxyError {
    Proxy(String),

    Internal(String),

    BadGateway(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proxy(msg) => write!(f, "proxy error: {}", msg),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
            Self::BadGateway(msg) => write!(f, "bad gateway: {}", msg),
        }
    }
}

impl std::error::Error for ProxyError {}

impl ProxyError {
    pub fn proxy(msg: impl Into<String>) -> Self {
        Self::Proxy(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    pub fn bad_gateway(msg: impl Into<String>) -> Self {
        Self::BadGateway(msg.into())
    }
}

/// 将 `reqwest::Error` 连同其 `source` 链格式化为可诊断的错误信息。
///
/// `reqwest::Error` 的 `Display` 只输出顶层原因（例如
/// `error sending request for url (...)`），真正的底层原因（超时、连接被重置、
/// TLS 握手失败等）保存在 `source` 链中。不展开 source 链会导致线上日志无法定位问题。
pub fn reqwest_error(prefix: &str, e: reqwest::Error) -> ProxyError {
    let mut msg: String = format!("{}: {}", prefix, e);
    if e.is_timeout() {
        msg.push_str(" [timeout]");
    } else if e.is_connect() {
        msg.push_str(" [connect]");
    } else if e.is_body() {
        msg.push_str(" [body]");
    }

    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
    while let Some(s) = src {
        msg.push_str(" -> ");
        msg.push_str(&s.to_string());
        src = std::error::Error::source(s);
    }

    ProxyError::proxy(msg)
}
