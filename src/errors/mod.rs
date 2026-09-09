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
