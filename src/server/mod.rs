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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tower::limit::ConcurrencyLimitLayer;
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
    /// Maximum RSS (memory usage) in bytes before rejecting requests.
    pub max_rss_bytes: u64,
    /// Directories allowed for local file path analysis via /analyze-path endpoint.
    /// Empty means the feature is disabled.
    /// DANGEROUS: Only enable when server is bound to localhost.
    pub allowed_local_paths: Vec<std::path::PathBuf>,
    /// Directory for extracting archive contents.
    /// When set, archive members are extracted here and paths are included in responses.
    pub extract_dir: Option<std::path::PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            qps: 100,
            timeout_secs: 120,
            max_body_size: 100 * 1024 * 1024,      // 100 MB
            max_rss_bytes: 8 * 1024 * 1024 * 1024, // 8 GB
            allowed_local_paths: Vec::new(),
            extract_dir: None,
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
    /// Maximum RSS in bytes before rejecting requests.
    pub max_rss_bytes: u64,
    /// Directories allowed for local file path analysis.
    /// Empty means the feature is disabled.
    pub allowed_local_paths: Vec<std::path::PathBuf>,
    /// Directory for extracting archive contents.
    pub extract_dir: Option<std::path::PathBuf>,
    /// Request ID counter.
    pub next_request_id: AtomicU64,
    /// Number of active analysis tasks.
    pub active_tasks: AtomicUsize,
}

impl AppState {
    /// Get the next unique request ID.
    pub fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::SeqCst)
    }
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

    let allowed_local_paths = config.allowed_local_paths.clone();
    let extract_dir = config.extract_dir.clone();

    if !allowed_local_paths.is_empty() {
        eprintln!(
            "WARNING: /analyze-path endpoint enabled for directories: {:?}",
            allowed_local_paths
        );
    }
    if let Some(ref dir) = extract_dir {
        eprintln!("Extract directory: {:?}", dir);
    }

    let state = Arc::new(AppState {
        rate_limiter: RateLimiter::new(config.qps),
        timeout_secs: config.timeout_secs,
        max_body_size: config.max_body_size,
        max_rss_bytes: config.max_rss_bytes,
        allowed_local_paths,
        extract_dir,
        next_request_id: AtomicU64::new(1),
        active_tasks: AtomicUsize::new(0),
    });

    // Spawn background task to clean up stale rate limiter entries
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            cleanup_state.rate_limiter.cleanup(300); // 5 minute expiry
        }
    });

    let max_concurrent = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(4)
        * 2;
    eprintln!("Max concurrent analyses: {}", max_concurrent);

    // Analysis routes with concurrency limit to prevent thread pool starvation.
    let analysis_routes = Router::new()
        .route("/analyze", post(handlers::analyze))
        .route("/analyze-path", post(handlers::analyze_path))
        .layer(ConcurrencyLimitLayer::new(max_concurrent));

    // Health/reload routes remain unrestricted.
    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/reload", post(handlers::reload))
        .merge(analysis_routes)
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
