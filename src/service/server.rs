use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::{Router, extract::OriginalUri, routing::any};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::config::{BackendConfig, RootConfig};
use crate::service::proxy::ProxyEngine;
use crate::service::webdav_handler::WebDavHandler;

use std::collections::HashMap;

struct AppState {
    handler: Arc<WebDavHandler>,

    cfg: Arc<BackendConfig>,
}

pub struct ServerManager {
    handles: HashMap<String, tokio::task::JoinHandle<()>>,

    shutdown_token: CancellationToken,
}

impl ServerManager {
    pub async fn new(cfg: &RootConfig) -> Result<Self, String> {
        let shutdown_token: CancellationToken = CancellationToken::new();
        let mut handles: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();

        for be in &cfg.backends {
            let addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], be.listen.port));
            let listener: TcpListener = TcpListener::bind(addr)
                .await
                .map_err(|e: std::io::Error| format!("failed to bind {:?}: {}", addr, e))?;

            let engine: ProxyEngine =
                ProxyEngine::new(be).map_err(|e: crate::errors::ProxyError| e.to_string())?;
            let engine: Arc<ProxyEngine> = Arc::new(engine);
            let be: Arc<BackendConfig> = Arc::new(be.clone());

            let handler: WebDavHandler = WebDavHandler::new(engine.clone(), be.clone());
            let state: Arc<AppState> = Arc::new(AppState {
                handler: Arc::new(handler),
                cfg: be.clone(),
            });

            let cors: CorsLayer = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    Method::GET,
                    Method::HEAD,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::OPTIONS,
                    Method::from_bytes(b"PROPFIND").unwrap(),
                    Method::from_bytes(b"PROPPATCH").unwrap(),
                    Method::from_bytes(b"MKCOL").unwrap(),
                    Method::from_bytes(b"COPY").unwrap(),
                    Method::from_bytes(b"MOVE").unwrap(),
                    Method::from_bytes(b"LOCK").unwrap(),
                    Method::from_bytes(b"UNLOCK").unwrap(),
                ])
                .allow_headers(Any);

            let app: Router = Router::new()
                .route("/", any(handle_request))
                .route("/{*path}", any(handle_request))
                .layer(cors)
                .with_state(state);

            let be_name: String = be.name.clone();
            let be_name_for_async: String = be_name.clone();
            let token: CancellationToken = shutdown_token.clone();

            let handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
                info!(
                    backend = %be_name_for_async,
                    addr = %addr,
                    upstream = %be.webdav_host.url,
                    "Backend started"
                );

                if let Err(e) = axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        token.cancelled().await;
                    })
                    .await
                {
                    warn!(error = %e, "Server stopped");
                }
            });

            handles.insert(be_name, handle);
        }

        Ok(Self {
            handles,
            shutdown_token,
        })
    }

    pub async fn shutdown(self) {
        self.shutdown_token.cancel();

        for (_name, handle) in self.handles {
            let _ = handle.await;
        }
    }
}

async fn handle_request(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,

    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<(StatusCode, HeaderMap, Body), StatusCode> {
    let display_path: String = uri.path().to_string();

    let mut headers: HeaderMap = headers.clone();
    WebDavHandler::inject_auth(&mut headers, &state.cfg);

    info!(method = %method, path = %display_path, "Request");

    match state
        .handler
        .handle(method.clone(), &display_path, headers, body)
        .await
    {
        Ok((status, resp_headers, resp_body)) => {
            info!(method = %method, path = %display_path, status = %status, "Response");
            Ok((status, resp_headers, resp_body))
        }
        Err(e) => {
            warn!(method = %method, path = %display_path, error = %e, "Handler error");

            let mut h: HeaderMap = HeaderMap::new();
            h.insert("Content-Type", HeaderValue::from_static("text/plain"));
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}
