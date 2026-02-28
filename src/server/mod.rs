//! HTTP API server for cleave file analysis.
//!
//! Provides a REST API for analyzing files without requiring CLI access.
//! Designed for integration with webber, trait-basher, and other tools.

mod handlers;
mod ratelimit;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

pub use ratelimit::RateLimiter;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to.
    pub bind: SocketAddr,
    /// Requests per second limit per IP.
    pub qps: u32,
    /// Analysis timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            qps: 100,
            timeout_secs: 120,
            max_body_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// Shared application state.
#[derive(Debug)]
pub struct AppState {
    /// Per-IP rate limiter.
    pub rate_limiter: RateLimiter,
    /// Analysis timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum request body size in bytes.
    pub max_body_size: usize,
}

/// Start the HTTP server with the given configuration.
///
/// This function blocks until the server is shut down via SIGINT/SIGTERM.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    eprintln!("Loading YARA rules and capability mapper...");

    // Force initialization of shared resources before accepting requests.
    // This takes ~27s but ensures fast first-request response.
    tokio::task::spawn_blocking(|| {
        // Trigger lazy initialization by analyzing an empty file
        let _ = crate::analyze_file("/dev/null", &crate::AnalysisOptions::default());
    })
    .await?;

    eprintln!("Resources loaded");

    let state = Arc::new(AppState {
        rate_limiter: RateLimiter::new(config.qps),
        timeout_secs: config.timeout_secs,
        max_body_size: config.max_body_size,
    });

    // Spawn background task to clean up stale rate limiter entries
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_state.rate_limiter.cleanup(300); // 5 minute expiry
        }
    });

    // Layer order matters: outermost (last added) runs first.
    // We want: rate limit -> body size limit -> handler
    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/analyze", post(analyze_with_headers))
        .layer(RequestBodyLimitLayer::new(config.max_body_size))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            rate_limit_middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind).await?;

    eprintln!(
        "Listening on http://{} (rate limit: {} req/s, timeout: {}s, max size: {} MB)",
        config.bind,
        config.qps,
        config.timeout_secs,
        config.max_body_size / 1024 / 1024
    );
    eprintln!("Press Ctrl+C to stop");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    eprintln!("Server shut down");
    Ok(())
}

/// Wrapper to extract Content-Type header and client IP, then pass to analyze handler.
async fn analyze_with_headers(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let client_ip = addr.ip();
    let content_type = request.headers().get("content-type").cloned();
    let max_size = state.max_body_size;
    let body = match axum::body::to_bytes(request.into_body(), max_size).await {
        Ok(b) => b,
        Err(e) => {
            warn!(%client_ip, "Failed to read request body: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Failed to read request body"})),
            )
                .into_response();
        }
    };
    handlers::analyze(Arc::clone(&state), client_ip, body, content_type).await
}

/// Rate limiting middleware.
async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    if !state.rate_limiter.check(ip) {
        warn!(%ip, "Rate limited");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Rate limit exceeded"})),
        )
            .into_response();
    }

    next.run(request).await
}

/// Wait for shutdown signal (SIGINT or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            warn!("Failed to install Ctrl+C handler: {}", e);
            // Fall back to pending forever
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                warn!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received SIGINT"),
        _ = terminate => info!("Received SIGTERM"),
    }
}
