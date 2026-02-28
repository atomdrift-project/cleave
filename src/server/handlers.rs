//! HTTP request handlers for the cleave API server.

use crate::{analyze_file, AnalysisOptions, Criticality};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use multer::Multipart;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tracing::{info, warn};

use super::AppState;

/// Health check endpoint.
pub(super) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
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

    // Get filename if provided
    let filename = field.file_name().map(String::from).unwrap_or_default();

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
        tokio::task::spawn_blocking(move || {
            analyze_file(&path, &AnalysisOptions::default())
        })
        .await
    })
    .await;

    // tempfile is dropped here (auto-deleted)
    drop(temp_file);

    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Ok(Ok(Ok(report))) => {
            // Summarize findings for logging
            let hostile = report.findings.iter().filter(|f| f.crit == Criticality::Hostile).count();
            let suspicious = report.findings.iter().filter(|f| f.crit == Criticality::Suspicious).count();
            let notable = report.findings.iter().filter(|f| f.crit == Criticality::Notable).count();

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
            warn!(%client_ip, filename = %filename, elapsed_ms = elapsed_ms, "Analysis failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Analysis failed: {}", e)})),
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
