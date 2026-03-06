//! HTTP request handlers for the cleave API server.

use crate::{analyze_file, AnalysisOptions, Criticality};

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tracing::{info, info_span, warn, Instrument, Span};

use super::AppState;

/// Health check endpoint.
pub(super) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

/// Reload trait definitions from disk.
pub(super) async fn reload(State(state): State<Arc<AppState>>) -> Response {
    let request_id = state.next_request_id();
    let span = info_span!("reload", request_id);

    async {
        let start = Instant::now();
        let task_span = Span::current();
        let result = tokio::task::spawn_blocking(move || {
            let _enter = task_span.enter();
            crate::shared_resources::reload_capability_mapper()
        })
        .await;
        let elapsed_ms = start.elapsed().as_millis();

        match result {
            Ok((traits, composites)) => {
                info!(traits, composites, elapsed_ms, "Reload complete");
                Json(serde_json::json!({
                    "status": "ok",
                    "traits": traits,
                    "composites": composites,
                    "elapsed_ms": elapsed_ms,
                }))
                .into_response()
            }
            Err(e) => {
                warn!(elapsed_ms, "Reload task join error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Internal error"})),
                )
                    .into_response()
            }
        }
    }
    .instrument(span)
    .await
}

/// File analysis endpoint.
///
/// Accepts multipart/form-data with a single file field.
/// Returns the analysis report as JSON.
pub(super) async fn analyze(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: axum::extract::Multipart,
) -> Response {
    let client_ip = addr.ip();
    let request_id = state.next_request_id();
    let request_start = Instant::now();

    let span = info_span!("request", %client_ip, request_id);

    analyze_inner(state, &mut multipart, request_start)
        .instrument(span)
        .await
}

async fn analyze_inner(
    state: Arc<AppState>,
    multipart: &mut axum::extract::Multipart,
    request_start: Instant,
) -> Response {
    info!("--> POST /analyze");

    if let Some(rss) = crate::memory_tracker::current_rss() {
        if rss > state.max_rss_bytes {
            warn!(
                rss_mb = rss / 1024 / 1024,
                max_rss_mb = state.max_rss_bytes / 1024 / 1024,
                "Server overloaded: high memory usage"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Server overloaded (memory)"})),
            )
                .into_response();
        }
    }

    let mut field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            warn!("Bad request: no file field");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No file field in request"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Failed to parse multipart: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid multipart data"})),
            )
                .into_response();
        }
    };

    let filename = field
        .file_name()
        .map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(255)
                .collect::<String>()
        })
        .unwrap_or_default();

    let temp_file = match tokio::task::spawn_blocking(NamedTempFile::new).await {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => {
            warn!("Failed to create temp file: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Task join error creating temp file: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };

    let path = temp_file.path().to_owned();
    let mut tokio_file = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to open temp file for async writing: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };

    let mut file_size = 0;
    while let Ok(Some(chunk)) = field.chunk().await {
        if chunk.is_empty() {
            continue;
        }
        file_size += chunk.len();
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut tokio_file, &chunk).await {
            warn!("Failed to write chunk to temp file: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to save file data"})),
            )
                .into_response();
        }
    }

    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut tokio_file).await {
        warn!("Failed to flush temp file: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to save file data"})),
        )
            .into_response();
    }

    if file_size == 0 {
        warn!("Bad request: empty file");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Empty file"})),
        )
            .into_response();
    }

    info!(size = file_size, filename = %filename, "Starting analysis");

    let timeout_duration = Duration::from_secs(state.timeout_secs);
    state
        .active_tasks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let task_span = Span::current();

    let result = tokio::time::timeout(timeout_duration, async move {
        tokio::task::spawn_blocking(move || {
            let _enter = task_span.enter();
            analyze_file(&path, &AnalysisOptions::default())
        })
        .await
    })
    .await;

    state
        .active_tasks
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    drop(temp_file);
    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Ok(Ok(Ok(mut report))) => {
            let hostile = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Hostile)
                .count();
            let suspicious = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Suspicious)
                .count();
            let notable = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Notable)
                .count();
            let baseline = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Baseline)
                .count();

            info!(
                filename = %filename, size = file_size, elapsed_ms = elapsed_ms,
                hostile = hostile, suspicious = suspicious, notable = notable, baseline = baseline, total = report.findings.len(),
                "<-- 200 OK (Analysis complete)"
            );
            report.finalize();
            Json(report).into_response()
        }
        Ok(Ok(Err(e))) => {
            warn!(filename = %filename, elapsed_ms = elapsed_ms, "Analysis failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Analysis failed"})),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            warn!(filename = %filename, elapsed_ms = elapsed_ms, "Task join error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response()
        }
        Err(_) => {
            warn!(filename = %filename, elapsed_ms = elapsed_ms, "Analysis timed out after {}s", state.timeout_secs);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Analysis timed out"})),
            )
                .into_response()
        }
    }
}

/// Extract a file to the extract directory.
/// Returns the extracted path if successful.
///
/// Files are organized as: `<extract_dir>/<sha256[0:6]>/<filename>`
fn extract_file_to_dir(source_path: &Path, extract_dir: &Path, sha256: &str) -> Option<String> {
    // Use first 6 chars of SHA256 for the subdirectory
    let short_sha = if sha256.len() >= 6 {
        &sha256[..6]
    } else {
        sha256
    };

    let sha_dir = extract_dir.join(short_sha);
    let filename = source_path.file_name()?;
    let dest_path = sha_dir.join(filename);

    // Skip if file already exists with same size
    if let Ok(dest_meta) = std::fs::metadata(&dest_path) {
        if let Ok(src_meta) = std::fs::metadata(source_path) {
            if dest_meta.len() == src_meta.len() {
                return Some(dest_path.display().to_string());
            }
        }
    }

    // Create directory and copy file
    if std::fs::create_dir_all(&sha_dir).is_err() {
        return None;
    }

    if std::fs::copy(source_path, &dest_path).is_err() {
        return None;
    }

    Some(dest_path.display().to_string())
}

/// Request body for /analyze-path endpoint.
#[derive(Debug, Deserialize)]
pub(super) struct AnalyzePathRequest {
    /// Absolute path to the file to analyze.
    pub path: String,
}

/// Response wrapper for /analyze-path endpoint.
/// Includes the analysis report plus extraction info.
#[derive(Debug, Serialize)]
struct AnalyzePathResponse {
    /// The analysis report
    #[serde(flatten)]
    report: crate::AnalysisReport,
    /// Path where the file was extracted (if extract_dir is configured)
    #[serde(skip_serializing_if = "Option::is_none")]
    extracted_path: Option<String>,
}

/// Analyze a local file by path.
///
/// DANGEROUS: Only available when server is started with --dangerous-local-file-paths.
/// Accepts JSON body: `{"path": "/absolute/path/to/file"}`
pub(super) async fn analyze_path(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<AnalyzePathRequest>,
) -> Response {
    let request_id = state.next_request_id();
    let client_ip = addr.ip();
    let request_start = Instant::now();

    let span = info_span!("request-path", %client_ip, request_id, path = %request.path);

    analyze_path_inner(state, request, request_start)
        .instrument(span)
        .await
}

async fn analyze_path_inner(
    state: Arc<AppState>,
    request: AnalyzePathRequest,
    request_start: Instant,
) -> Response {
    info!("--> POST /analyze-path");

    // Check memory pressure before accepting work
    if let Some(rss) = crate::memory_tracker::current_rss() {
        if rss > state.max_rss_bytes {
            warn!(
                rss_mb = rss / 1024 / 1024,
                max_rss_mb = state.max_rss_bytes / 1024 / 1024,
                "Server overloaded: high memory usage"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Server overloaded (memory)"})),
            )
                .into_response();
        }
    }

    // Check if local path analysis is enabled
    if state.allowed_local_paths.is_empty() {
        warn!("Rejected /analyze-path request: feature not enabled");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Local file path analysis is not enabled"})),
        )
            .into_response();
    }

    let path = Path::new(&request.path);

    // Validate path is absolute
    if !path.is_absolute() {
        warn!(path = %request.path, "Rejected relative path");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Path must be absolute"})),
        )
            .into_response();
    }

    // Canonicalize the path to resolve symlinks and ..
    let Ok(canonical_path) = path.canonicalize() else {
        warn!(path = %request.path, "File not found or not accessible");
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "File not found"})),
        )
            .into_response();
    };

    // Check path is within allowed directories
    let allowed = state
        .allowed_local_paths
        .iter()
        .any(|allowed_dir| canonical_path.starts_with(allowed_dir));

    if !allowed {
        warn!(
            path = %request.path,
            canonical = %canonical_path.display(),
            "Path not in allowed directories"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Path not in allowed directories"})),
        )
            .into_response();
    }

    // File existence already verified by canonicalize()
    let path = canonical_path;
    let path_str = request.path.clone();
    let extract_dir = state.extract_dir.clone();

    info!(path = %path_str, "Starting analysis");

    let timeout_duration = Duration::from_secs(state.timeout_secs);
    let path_owned = path.to_owned();
    let task_span = Span::current();

    // Run analysis in blocking thread with timeout
    let result = tokio::time::timeout(timeout_duration, async move {
        tokio::task::spawn_blocking(move || {
            let _enter = task_span.enter();
            analyze_file(&path_owned, &AnalysisOptions::default())
        })
        .await
    })
    .await;

    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Ok(Ok(Ok(mut report))) => {
            let hostile = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Hostile)
                .count();
            let suspicious = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Suspicious)
                .count();
            let notable = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Notable)
                .count();
            let baseline = report
                .findings
                .iter()
                .filter(|f| f.crit == Criticality::Baseline)
                .count();

            // Extract file to extract_dir if configured
            let extracted_path = if let Some(ref extract_base) = extract_dir {
                extract_file_to_dir(&path, extract_base, &report.target.sha256)
            } else {
                None
            };

            info!(
                path = %path_str,
                elapsed_ms = elapsed_ms,
                hostile = hostile,
                suspicious = suspicious,
                notable = notable,
                baseline = baseline,
                total = report.findings.len(),
                extracted_path = ?extracted_path,
                "<-- 200 OK (Analysis complete)"
            );

            report.finalize();
            let response = AnalyzePathResponse {
                report,
                extracted_path,
            };
            Json(response).into_response()
        }
        Ok(Ok(Err(e))) => {
            warn!(path = %path_str, elapsed_ms = elapsed_ms, "Analysis failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Analysis failed"})),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            warn!(path = %path_str, elapsed_ms = elapsed_ms, "Task join error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response()
        }
        Err(_) => {
            warn!(path = %path_str, elapsed_ms = elapsed_ms, "Analysis timed out after {}s", state.timeout_secs);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Analysis timed out"})),
            )
                .into_response()
        }
    }
}
