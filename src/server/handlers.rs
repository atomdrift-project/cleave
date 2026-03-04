//! HTTP request handlers for the cleave API server.

use crate::{analyze_file, AnalysisOptions, Criticality};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use multer::Multipart;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tracing::{info, warn};

use super::AppState;

/// Health check endpoint.
pub(super) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

/// Reload trait definitions from disk.
pub(super) async fn reload() -> Response {
    let start = Instant::now();
    let result = tokio::task::spawn_blocking(crate::shared_resources::reload_capability_mapper).await;
    let elapsed_ms = start.elapsed().as_millis();

    match result {
        Ok(Ok((traits, composites))) => {
            info!(traits, composites, elapsed_ms, "Reload complete");
            Json(serde_json::json!({
                "status": "ok",
                "traits": traits,
                "composites": composites,
                "elapsed_ms": elapsed_ms,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            warn!(elapsed_ms, "Reload failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e})),
            )
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

/// File analysis endpoint.
///
/// Accepts multipart/form-data with a single file field.
/// Returns the analysis report as JSON.
pub(super) async fn analyze(
    state: Arc<AppState>,
    client_ip: IpAddr,
    body: Bytes,
    content_type: Option<axum::http::HeaderValue>,
) -> Response {
    let request_start = Instant::now();

    // Extract boundary from content-type header
    let Some(boundary) = extract_boundary(content_type.as_ref()) else {
        warn!(%client_ip, "Bad request: missing or invalid Content-Type");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing or invalid Content-Type header"})),
        )
            .into_response();
    };

    // Parse multipart
    let mut multipart = Multipart::new(body_to_stream(body), boundary);

    // Extract the file field
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            warn!(%client_ip, "Bad request: no file field");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No file field in request"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(%client_ip, "Failed to parse multipart: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid multipart data"})),
            )
                .into_response();
        }
    };

    // Get filename if provided, sanitize for logging (truncate, remove control chars)
    let filename = field
        .file_name()
        .map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(255)
                .collect::<String>()
        })
        .unwrap_or_default();

    // Read file data
    let data = match field.bytes().await {
        Ok(d) => d,
        Err(e) => {
            warn!(%client_ip, "Failed to read file data: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Failed to read file data"})),
            )
                .into_response();
        }
    };

    if data.is_empty() {
        warn!(%client_ip, "Bad request: empty file");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Empty file"})),
        )
            .into_response();
    }

    let file_size = data.len();
    info!(%client_ip, size = file_size, filename = %filename, "Analyzing file");

    // Write to tempfile
    let temp_file = match write_temp_file(&data) {
        Ok(f) => f,
        Err(e) => {
            warn!(%client_ip, "Failed to create temp file: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };

    let path = temp_file.path().to_owned();
    let timeout_duration = Duration::from_secs(state.timeout_secs);

    // Run analysis in blocking thread with timeout
    let result = tokio::time::timeout(timeout_duration, async {
        tokio::task::spawn_blocking(move || analyze_file(&path, &AnalysisOptions::default())).await
    })
    .await;

    // tempfile is dropped here (auto-deleted)
    drop(temp_file);

    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Ok(Ok(Ok(report))) => {
            // Summarize findings for logging
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

            info!(
                %client_ip,
                filename = %filename,
                size = file_size,
                elapsed_ms = elapsed_ms,
                hostile = hostile,
                suspicious = suspicious,
                notable = notable,
                findings = report.findings.len(),
                "Analysis complete"
            );

            Json(report).into_response()
        }
        Ok(Ok(Err(e))) => {
            // Log full error internally, return generic message to client
            warn!(%client_ip, filename = %filename, elapsed_ms = elapsed_ms, "Analysis failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Analysis failed"})),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            warn!(%client_ip, filename = %filename, elapsed_ms = elapsed_ms, "Task join error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response()
        }
        Err(_) => {
            warn!(%client_ip, filename = %filename, elapsed_ms = elapsed_ms, "Analysis timed out after {}s", state.timeout_secs);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Analysis timed out"})),
            )
                .into_response()
        }
    }
}

/// Write bytes to a temporary file.
fn write_temp_file(data: &[u8]) -> std::io::Result<NamedTempFile> {
    let mut temp = NamedTempFile::new()?;
    temp.write_all(data)?;
    temp.flush()?;
    Ok(temp)
}

/// Extract multipart boundary from Content-Type header.
fn extract_boundary(content_type: Option<&axum::http::HeaderValue>) -> Option<String> {
    let ct = content_type?.to_str().ok()?;
    if !ct.starts_with("multipart/form-data") {
        return None;
    }
    ct.split(';').find_map(|part| {
        part.trim()
            .strip_prefix("boundary=")
            .map(|b| b.trim_matches('"').to_string())
    })
}

/// Convert Bytes to a stream for multer.
fn body_to_stream(body: Bytes) -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::once(async move { Ok(body) })
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
    let client_ip = addr.ip();

    // Check if local path analysis is enabled
    if state.allowed_local_paths.is_empty() {
        warn!(%client_ip, "Rejected /analyze-path request: feature not enabled");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Local file path analysis is not enabled"})),
        )
            .into_response();
    }

    let path = Path::new(&request.path);

    // Validate path is absolute
    if !path.is_absolute() {
        warn!(%client_ip, path = %request.path, "Rejected relative path");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Path must be absolute"})),
        )
            .into_response();
    }

    // Canonicalize the path to resolve symlinks and ..
    let Ok(canonical_path) = path.canonicalize() else {
        warn!(%client_ip, path = %request.path, "File not found or not accessible");
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
            %client_ip,
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

    let request_start = Instant::now();
    let path_str = request.path.clone();
    let extract_dir = state.extract_dir.clone();

    info!(%client_ip, path = %path_str, "Analyzing local file");

    let timeout_duration = Duration::from_secs(state.timeout_secs);
    let path_owned = path.to_owned();

    // Run analysis in blocking thread with timeout
    let result = tokio::time::timeout(timeout_duration, async {
        tokio::task::spawn_blocking(move || analyze_file(&path_owned, &AnalysisOptions::default()))
            .await
    })
    .await;

    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Ok(Ok(Ok(report))) => {
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

            // Extract file to extract_dir if configured
            let extracted_path = if let Some(ref extract_base) = extract_dir {
                extract_file_to_dir(&path, extract_base, &report.target.sha256)
            } else {
                None
            };

            info!(
                %client_ip,
                path = %path_str,
                elapsed_ms = elapsed_ms,
                hostile = hostile,
                suspicious = suspicious,
                notable = notable,
                findings = report.findings.len(),
                extracted_path = ?extracted_path,
                "Analysis complete"
            );

            let response = AnalyzePathResponse {
                report,
                extracted_path,
            };
            Json(response).into_response()
        }
        Ok(Ok(Err(e))) => {
            warn!(%client_ip, path = %path_str, elapsed_ms = elapsed_ms, "Analysis failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Analysis failed"})),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            warn!(%client_ip, path = %path_str, elapsed_ms = elapsed_ms, "Task join error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response()
        }
        Err(_) => {
            warn!(%client_ip, path = %path_str, elapsed_ms = elapsed_ms, "Analysis timed out after {}s", state.timeout_secs);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Analysis timed out"})),
            )
                .into_response()
        }
    }
}
