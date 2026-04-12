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
use tempfile::Builder as TempBuilder;
use tracing::{info, info_span, warn, Instrument, Span};

use super::AppState;

fn analysis_error_response(error: &anyhow::Error) -> Response {
    let (status, message) = classify_analysis_error(error.root_cause().to_string().as_str());
    let detail = format!("{error:#}");

    (
        status,
        Json(if detail == message {
            serde_json::json!({ "error": message })
        } else {
            serde_json::json!({ "error": message, "detail": detail })
        }),
    )
        .into_response()
}

fn classify_analysis_error(message: &str) -> (StatusCode, String) {
    let normalized = message.to_ascii_lowercase();

    let status = if normalized.contains("unsupported file type")
        || normalized.contains("unsupported archive type")
        || normalized.contains("unsupported compression")
    {
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    } else if normalized.contains("archive is encrypted but no passwords configured")
        || normalized.contains("invalid ")
        || normalized.contains("not a valid ")
        || normalized.contains("truncated")
        || normalized.contains("too small")
        || normalized.contains("out of bounds")
        || normalized.contains("empty package.json")
        || normalized.contains("maximum archive depth")
        || normalized.contains("maximum decode depth")
        || normalized.contains("exceeded maximum")
        || normalized.contains("file count limit exceeded")
    {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    (status, message.to_string())
}

fn analysis_error_status(error: &anyhow::Error) -> StatusCode {
    classify_analysis_error(error.root_cause().to_string().as_str()).0
}

/// Health check endpoint. Returns 200 OK when healthy, 503 when memory-overloaded or thread pool saturated.
pub(super) async fn health(State(state): State<Arc<AppState>>) -> Response {
    let rss_bytes = crate::memory_tracker::current_rss().unwrap_or(0);
    let rss_mb = rss_bytes / 1024 / 1024;
    let active_tasks = state
        .active_tasks
        .load(std::sync::atomic::Ordering::Relaxed);
    let overloaded = rss_bytes > 0 && rss_bytes > state.max_rss_bytes;
    if overloaded {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "reason": "memory_pressure",
                "rss_mb": rss_mb,
                "max_rss_mb": state.max_rss_bytes / 1024 / 1024,
                "active_tasks": active_tasks,
                "rayon_threads": rayon::current_num_threads(),
            })),
        )
            .into_response();
    }
    let recycled_orphans = state
        .recycled_orphans
        .load(std::sync::atomic::Ordering::Relaxed);
    if active_tasks >= state.max_concurrent_tasks {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "reason": "thread_pool_saturated",
                "rss_mb": rss_mb,
                "active_tasks": active_tasks,
                "max_concurrent_tasks": state.max_concurrent_tasks,
                "recycled_orphans": recycled_orphans,
                "rayon_threads": rayon::current_num_threads(),
            })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "status": "ok",
        "rss_mb": rss_mb,
        "active_tasks": active_tasks,
        "recycled_orphans": recycled_orphans,
        "rayon_threads": rayon::current_num_threads(),
    }))
    .into_response()
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
            Ok(Err(msg)) => {
                warn!(
                    elapsed_ms,
                    "Reload failed (previous rules retained): {}", msg
                );
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "error": "Failed to load new traits",
                        "detail": msg,
                        "elapsed_ms": elapsed_ms,
                    })),
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

    analyze_inner(state, &mut multipart, request_start, request_id)
        .instrument(span)
        .await
}

async fn analyze_inner(
    state: Arc<AppState>,
    multipart: &mut axum::extract::Multipart,
    request_start: Instant,
    request_id: u64,
) -> Response {
    info!("--> POST /analyze");

    if let Some(response) = check_memory_pressure(&state) {
        return response;
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

    // Create a temp directory containing a file with the original filename so that
    // fileid's filename-based type detection works correctly (e.g. "package.json"
    // is recognized as PackageJson, not Unknown).
    let sanitized_filename = if filename.is_empty() {
        "upload".to_string()
    } else {
        // Sanitize: keep alphanumeric, dots, hyphens, underscores; collapse ".."
        filename
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .replace("..", "__")
    };
    let temp_dir =
        match tokio::task::spawn_blocking(move || TempBuilder::new().prefix("cleave-").tempdir())
            .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                warn!("Failed to create temp dir: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Internal error"})),
                )
                    .into_response();
            }
            Err(e) => {
                warn!("Task join error creating temp dir: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Internal error"})),
                )
                    .into_response();
            }
        };

    let path = temp_dir.path().join(&sanitized_filename);
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

    // Hard gate: reject if too many analysis tasks are running (including orphans).
    // This prevents timed-out-but-still-running blocking tasks from piling up
    // and consuming unbounded memory over long server lifetimes.
    let active = state
        .active_tasks
        .load(std::sync::atomic::Ordering::Relaxed);
    if active >= state.max_concurrent_tasks {
        warn!(
            active_tasks = active,
            max = state.max_concurrent_tasks,
            "Rejecting request: too many active analysis tasks (including orphans)"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Server overloaded (too many active analyses)"})),
        )
            .into_response();
    }

    let timeout_duration = Duration::from_secs(state.timeout_secs);
    state
        .active_tasks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.in_flight.insert(
        request_id,
        super::InFlightRequest {
            name: filename.clone(),
            size_bytes: file_size as u64,
            started_at: Instant::now(),
        },
    );
    let task_span = Span::current();

    let should_clear_caches = state
        .next_request_id
        .load(std::sync::atomic::Ordering::Relaxed)
        .is_multiple_of(50);
    let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancellation_for_task = cancellation.clone();
    let mut handle = tokio::task::spawn_blocking(move || {
        let _enter = task_span.enter();
        let opts = AnalysisOptions {
            cancellation: Some(cancellation_for_task),
            ..AnalysisOptions::default()
        };
        let result = analyze_file(&path, &opts);
        if should_clear_caches {
            crate::clear_all_thread_caches();
        }
        result
    });

    let result = tokio::select! {
        res = &mut handle => Some(res),
        _ = tokio::time::sleep(timeout_duration) => None,
    };

    // On success/error, the blocking task is done — decrement and clean up.
    // On timeout, signal cancellation and give the task a short grace period.
    if result.is_some() {
        state
            .active_tasks
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        state.in_flight.remove(&request_id);
        drop(temp_dir);
    } else {
        cancellation.store(true, std::sync::atomic::Ordering::Release);
        let active = state
            .active_tasks
            .load(std::sync::atomic::Ordering::Relaxed);
        warn!(
            filename = %filename,
            active_tasks = active,
            "Analysis timed out but blocking task still running"
        );
        let orphan_state = Arc::clone(&state);
        let orphan_timeout = Duration::from_secs(1800);
        tokio::spawn(async move {
            // Phase 1: wait up to the grace period for the task to finish.
            let grace_result = tokio::time::timeout(orphan_timeout, &mut handle).await;
            orphan_state.in_flight.remove(&request_id);

            // Release the slot regardless — the thread is stuck on a file-specific
            // operation, so a new request for a different file won't hit the same issue.
            orphan_state
                .active_tasks
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            if grace_result.is_ok() {
                drop(temp_dir);
                tracing::info!(request_id, "Orphaned task completed during grace period");
                return;
            }

            let recycled = orphan_state
                .recycled_orphans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::error!(
                request_id,
                recycled_orphans = recycled,
                "Orphaned analysis task exceeded grace period, slot recycled — still awaiting thread join"
            );

            // Phase 2: keep waiting (unbounded) so the thread is properly joined
            // and its resources (temp files, allocations) are reclaimed when it
            // eventually finishes. Without this, the JoinHandle is dropped and
            // the thread is detached forever.
            let _ = handle.await;
            drop(temp_dir);
            orphan_state
                .recycled_orphans
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                request_id,
                "Detached orphan finally completed and was joined"
            );
        });
    }
    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Some(Ok(Ok(mut report))) => {
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
            let compact = crate::types::compact_from_files(&report.files);
            Json(compact).into_response()
        }
        Some(Ok(Err(e))) => {
            let status = analysis_error_status(&e);
            warn!(filename = %filename, elapsed_ms = elapsed_ms, status = status.as_u16(), "Analysis failed: {:?}", e);
            analysis_error_response(&e)
        }
        Some(Err(e)) => {
            warn!(filename = %filename, elapsed_ms = elapsed_ms, "Task join error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response()
        }
        None => {
            warn!(filename = %filename, elapsed_ms = elapsed_ms, "Analysis timed out after {}s", state.timeout_secs);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Analysis timed out"})),
            )
                .into_response()
        }
    }
}

/// Check memory pressure and attempt recovery before rejecting requests.
///
/// Returns `Some(Response)` if the request should be rejected due to memory pressure,
/// or `None` if the server has enough memory to proceed.
fn check_memory_pressure(state: &AppState) -> Option<Response> {
    let rss = crate::memory_tracker::current_rss()?;

    if rss <= state.max_rss_bytes {
        // Memory is fine — reset overload timer if it was set.
        // Use try_lock to avoid contention on the happy path.
        if let Some(mut overloaded) = state.overloaded_since.try_lock() {
            if overloaded.is_some() {
                info!(
                    rss_mb = rss / 1024 / 1024,
                    "Memory recovered below threshold"
                );
                *overloaded = None;
            }
        }
        return None;
    }

    // Memory pressure detected — try to reclaim by clearing thread-local caches.
    // Use block_in_place so tokio knows this thread will block on rayon::broadcast.
    info!(
        rss_mb = rss / 1024 / 1024,
        "Memory pressure detected, clearing thread-local caches"
    );
    tokio::task::block_in_place(crate::clear_all_thread_caches);

    // Re-check after clearing caches
    let rss_after = crate::memory_tracker::current_rss()?;
    if rss_after <= state.max_rss_bytes {
        // Memory recovered — reset overload timer
        *state.overloaded_since.lock() = None;
        info!(
            rss_before_mb = rss / 1024 / 1024,
            rss_after_mb = rss_after / 1024 / 1024,
            "Cache clear freed memory, accepting request"
        );
        return None;
    }

    // Still overloaded — track duration and keep rejecting requests until the
    // process recovers or an external supervisor restarts it.
    let mut overloaded = state.overloaded_since.lock();
    let since = *overloaded.get_or_insert_with(Instant::now);
    let overloaded_secs = since.elapsed().as_secs();

    if overloaded_secs > 30 {
        tracing::error!(
            rss_mb = rss_after / 1024 / 1024,
            overloaded_secs,
            "Memory overload persisted >30s after cache clears; continuing to reject requests"
        );
    }

    warn!(
        rss_mb = rss_after / 1024 / 1024,
        max_rss_mb = state.max_rss_bytes / 1024 / 1024,
        overloaded_secs,
        "Server overloaded: high memory usage (even after cache clear)"
    );
    Some(
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Server overloaded (memory)"})),
        )
            .into_response(),
    )
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
    /// The analysis report (compact v4)
    #[serde(flatten)]
    report: crate::types::compact::CompactReport,
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

    analyze_path_inner(state, request, request_start, request_id)
        .instrument(span)
        .await
}

async fn analyze_path_inner(
    state: Arc<AppState>,
    request: AnalyzePathRequest,
    request_start: Instant,
    request_id: u64,
) -> Response {
    info!("--> POST /analyze-path");

    if let Some(response) = check_memory_pressure(&state) {
        return response;
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

    // Hard gate: reject if too many analysis tasks are running (including orphans).
    let active = state
        .active_tasks
        .load(std::sync::atomic::Ordering::Relaxed);
    if active >= state.max_concurrent_tasks {
        warn!(
            active_tasks = active,
            max = state.max_concurrent_tasks,
            "Rejecting request: too many active analysis tasks (including orphans)"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Server overloaded (too many active analyses)"})),
        )
            .into_response();
    }

    let timeout_duration = Duration::from_secs(state.timeout_secs);
    let path_owned = path.to_owned();
    let task_span = Span::current();

    // Run analysis in blocking thread with timeout
    // Use the request counter to periodically clear caches (avoids rayon::broadcast on every request)
    let should_clear_caches = state
        .next_request_id
        .load(std::sync::atomic::Ordering::Relaxed)
        .is_multiple_of(50);
    let size_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    state
        .active_tasks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.in_flight.insert(
        request_id,
        super::InFlightRequest {
            name: path_str.clone(),
            size_bytes,
            started_at: Instant::now(),
        },
    );
    let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let extract_dir_for_response = extract_dir.clone();
    let cancellation_for_task = cancellation.clone();
    let mut handle = tokio::task::spawn_blocking(move || {
        let _enter = task_span.enter();
        let mut opts = AnalysisOptions::default();
        if let Some(dir) = extract_dir {
            opts.sample_extraction = Some(crate::SampleExtractionConfig::new(dir));
        }
        opts.cancellation = Some(cancellation_for_task);
        let result = analyze_file(&path_owned, &opts);
        // Periodically clear thread-local caches to prevent unbounded memory growth.
        // Done every 50 requests rather than every request to avoid rayon::broadcast
        // contention under concurrent load.
        if should_clear_caches {
            crate::clear_all_thread_caches();
        }
        result
    });

    let result = tokio::select! {
        res = &mut handle => Some(res),
        _ = tokio::time::sleep(timeout_duration) => None,
    };

    // Decrement active tasks on completion; on timeout, spawn a watcher
    // that gives the task a bounded grace period before abandoning it.
    if result.is_some() {
        state
            .active_tasks
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        state.in_flight.remove(&request_id);
    } else {
        cancellation.store(true, std::sync::atomic::Ordering::Release);
        let active = state
            .active_tasks
            .load(std::sync::atomic::Ordering::Relaxed);
        warn!(
            path = %path_str,
            active_tasks = active,
            "Analysis timed out but blocking task still running"
        );
        let orphan_state = Arc::clone(&state);
        let orphan_timeout = Duration::from_secs(1800);
        tokio::spawn(async move {
            let grace_result = tokio::time::timeout(orphan_timeout, &mut handle).await;
            orphan_state.in_flight.remove(&request_id);
            orphan_state
                .active_tasks
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            if grace_result.is_ok() {
                tracing::info!(request_id, "Orphaned task completed during grace period");
                return;
            }

            let recycled = orphan_state
                .recycled_orphans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::error!(
                request_id,
                recycled_orphans = recycled,
                "Orphaned analysis task exceeded grace period, slot recycled — still awaiting thread join"
            );

            // Keep waiting so the thread is properly joined and its resources
            // are reclaimed when it eventually finishes.
            let _ = handle.await;
            orphan_state
                .recycled_orphans
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                request_id,
                "Detached orphan finally completed and was joined"
            );
        });
    }

    let elapsed_ms = request_start.elapsed().as_millis();

    match result {
        Some(Ok(Ok(mut report))) => {
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

            // Archive members are already extracted during analysis via sample_extraction.
            // Report the extract dir so callers know where to find them.
            let extracted_path = extract_dir_for_response
                .as_ref()
                .map(|d| d.display().to_string());

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
            let compact = crate::types::compact_from_files(&report.files);
            let response = AnalyzePathResponse {
                report: compact,
                extracted_path,
            };
            Json(response).into_response()
        }
        Some(Ok(Err(e))) => {
            let status = analysis_error_status(&e);
            warn!(path = %path_str, elapsed_ms = elapsed_ms, status = status.as_u16(), "Analysis failed: {:?}", e);
            analysis_error_response(&e)
        }
        Some(Err(e)) => {
            warn!(path = %path_str, elapsed_ms = elapsed_ms, "Task join error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal error"})),
            )
                .into_response()
        }
        None => {
            warn!(path = %path_str, elapsed_ms = elapsed_ms, "Analysis timed out after {}s", state.timeout_secs);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({"error": "Analysis timed out"})),
            )
                .into_response()
        }
    }
}

/// Memory diagnostics endpoint — exposes sizes of all major in-process structures.
///
/// Use this to track down memory leaks: poll it over time and watch which
/// counter grows while RSS grows.
pub(super) async fn memory_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // SQLite COUNT(*) can briefly block, so run it off the async thread.
    let cache_entries =
        tokio::task::spawn_blocking(crate::analysis_cache::report_cache_entry_count).await;
    let cache_entries = cache_entries.unwrap_or(None);

    let rss_mb = crate::memory_tracker::current_rss().map(|b| b / 1024 / 1024);

    // Jemalloc allocator stats — only populated when built with --features jemalloc.
    // `allocated` is the key number: actual live bytes vs RSS reveals fragmentation.
    let jemalloc = crate::memory_tracker::jemalloc_stats().map(|s| {
        serde_json::json!({
            "allocated_mb": s.allocated / 1024 / 1024,
            "active_mb":    s.active    / 1024 / 1024,
            "metadata_mb":  s.metadata  / 1024 / 1024,
            "resident_mb":  s.resident  / 1024 / 1024,
            "retained_mb":  s.retained  / 1024 / 1024,
            // fragmentation = active - allocated (holes jemalloc can't reuse yet)
            "fragmentation_mb": s.active.saturating_sub(s.allocated) / 1024 / 1024,
        })
    });

    let (regex_v2_entries, regex_v2_max) = {
        let cache = crate::composite_rules::evaluators::regex_cache_v2().read();
        (cache.len(), cache.cap().get())
    };

    let mapper_stats = crate::shared_resources::capability_mapper_stats();

    let (rizin_total, rizin_ok, rizin_timeouts, rizin_failures) = crate::radare2::rizin_stats();

    Json(serde_json::json!({
        "process": {
            "rss_mb": rss_mb,
            "max_rss_mb": state.max_rss_bytes / 1024 / 1024,
            // null when not built with --features jemalloc
            "jemalloc": jemalloc,
        },
        "server": {
            "active_tasks": state.active_tasks.load(std::sync::atomic::Ordering::Relaxed),
            "recycled_orphans": state.recycled_orphans.load(std::sync::atomic::Ordering::Relaxed),
            "requests_total": state.next_request_id.load(std::sync::atomic::Ordering::Relaxed),
            "rate_limiter_ips": state.rate_limiter.active_count(),
            "rate_limiter_max_ips": 50_000,
        },
        "caches": {
            "analysis_sqlite_entries": cache_entries,
            "analysis_sqlite_max": 100_000,
            "regex_v2_entries": regex_v2_entries,
            "regex_v2_max": regex_v2_max,
            // YARA scanner caches are thread-local; cap is per-thread
            "yara_scanner_max_per_thread": 4,
        },
        "capability_mapper": mapper_stats.map(|(traits, composites)| serde_json::json!({
            "traits": traits,
            "composites": composites,
        })),
        "rizin": {
            "total": rizin_total,
            "successes": rizin_ok,
            "timeouts": rizin_timeouts,
            "failures": rizin_failures,
        },
        "thread_pools": {
            "rayon_global_threads": rayon::current_num_threads(),
        },
    }))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::classify_analysis_error;
    use axum::http::StatusCode;

    #[test]
    fn classify_unsupported_file_type_as_415() {
        let (status, message) = classify_analysis_error("Unsupported file type: Unknown");
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(message, "Unsupported file type: Unknown");
    }

    #[test]
    fn classify_invalid_archive_as_422() {
        let (status, message) =
            classify_analysis_error("Archive is encrypted but no passwords configured");
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(message, "Archive is encrypted but no passwords configured");
    }

    #[test]
    fn classify_unexpected_failure_as_500() {
        let (status, _) = classify_analysis_error("YARA scan failed: scanner crashed");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

/// In-flight request list — shows every analysis currently running, with elapsed time.
pub(super) async fn requests(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let now = Instant::now();
    let mut entries: Vec<serde_json::Value> = state
        .in_flight
        .iter()
        .map(|e| {
            let elapsed_ms = now.duration_since(e.started_at).as_millis() as u64;
            serde_json::json!({
                "request_id": e.key(),
                "name": e.name,
                "size_bytes": e.size_bytes,
                "elapsed_ms": elapsed_ms,
            })
        })
        .collect();

    // Sort by elapsed descending so the longest-running request is first.
    entries.sort_by(|a, b| b["elapsed_ms"].as_u64().cmp(&a["elapsed_ms"].as_u64()));

    Json(serde_json::json!({
        "count": entries.len(),
        "requests": entries,
    }))
}

/// Thread list — shows OS-level info for every thread in this process.
///
/// On Linux: reads `/proc/self/task/` for thread name, state, and `wchan`
/// (the kernel function the thread is currently blocked on). `wchan` is the
/// single most useful field for diagnosing deadlocks — look for `futex_wait`
/// (mutex contention) or unexpected `futex_wait` in tokio worker threads.
///
/// On other platforms: returns thread count only.
pub(super) async fn threads() -> Json<serde_json::Value> {
    // Reading /proc is blocking I/O.
    let info = tokio::task::spawn_blocking(read_thread_info).await;
    let info = info.unwrap_or_else(|_| serde_json::json!({"error": "failed to read thread info"}));
    Json(info)
}

fn read_thread_info() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    return read_thread_info_linux();

    #[cfg(target_os = "freebsd")]
    return read_thread_info_freebsd();

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    serde_json::json!({
        "note": "detailed thread info only available on Linux and FreeBSD",
        "rayon_threads": rayon::current_num_threads(),
    })
}

#[cfg(target_os = "linux")]
fn read_thread_info_linux() -> serde_json::Value {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return serde_json::json!({"error": "cannot read /proc/self/task"});
    };

    let mut threads: Vec<serde_json::Value> = tasks
        .flatten()
        .filter_map(|entry| {
            let base = entry.path();
            let tid: u32 = entry.file_name().to_string_lossy().parse().ok()?;

            let name = std::fs::read_to_string(base.join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            // wchan: kernel function the thread is waiting in ("0" means running).
            let wchan = std::fs::read_to_string(base.join("wchan"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            // State and voluntary context switches from /proc/self/task/{tid}/status.
            let mut state = String::new();
            let mut vol_switches: u64 = 0;
            let mut nonvol_switches: u64 = 0;
            if let Ok(status) = std::fs::read_to_string(base.join("status")) {
                for line in status.lines() {
                    if let Some(val) = line.strip_prefix("State:\t") {
                        state = val.to_string();
                    } else if let Some(val) = line.strip_prefix("voluntary_ctxt_switches:\t") {
                        vol_switches = val.trim().parse().unwrap_or(0);
                    } else if let Some(val) = line.strip_prefix("nonvoluntary_ctxt_switches:\t") {
                        nonvol_switches = val.trim().parse().unwrap_or(0);
                    }
                }
            }

            Some(serde_json::json!({
                "tid": tid,
                "name": name,
                "state": state,
                // What kernel function this thread is blocked in.
                // "futex_wait*" = waiting on a mutex/condvar.
                // "do_epoll_wait" / "ep_poll" = tokio async sleep / I/O poll.
                // "0" or "" = currently running on CPU.
                "wchan": wchan,
                "voluntary_context_switches": vol_switches,
                "nonvoluntary_context_switches": nonvol_switches,
            }))
        })
        .collect();

    threads.sort_by_key(|t| t["tid"].as_u64().unwrap_or(0));

    serde_json::json!({
        "count": threads.len(),
        "threads": threads,
    })
}

/// Read thread info on FreeBSD using sysctl(KERN_PROC_PID | KERN_PROC_INC_THREAD).
///
/// Returns one `kinfo_proc` per thread. Key fields:
/// - `ki_tdname`: thread name (equivalent of Linux comm)
/// - `ki_wmesg`: wait message — what the thread is blocked on (equivalent of Linux wchan).
///   e.g. "futex" = mutex wait, "kqread" = kqueue/epoll, "nanslp" = sleep, "" = running.
/// - `ki_stat`: thread state (SRUN=2, SSLEEP=3, SWAIT=6, SLOCK=7, ...)
#[cfg(target_os = "freebsd")]
fn read_thread_info_freebsd() -> serde_json::Value {
    use std::mem;

    let pid = unsafe { libc::getpid() };

    // MIB: kern.proc.pid.<pid> with KERN_PROC_INC_THREAD to include all threads.
    let mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID | libc::KERN_PROC_INC_THREAD,
        pid,
    ];

    // First call: get required buffer size.
    let mut len: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            4,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return serde_json::json!({"error": "sysctl size query failed"});
    }

    // Add 25% slack — threads can be created between the two sysctl calls.
    len += len / 4;
    let count = len / mem::size_of::<libc::kinfo_proc>();
    let mut procs: Vec<libc::kinfo_proc> = (0..count).map(|_| unsafe { mem::zeroed() }).collect();
    let mut actual_len = len;

    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            4,
            procs.as_mut_ptr().cast(),
            &mut actual_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return serde_json::json!({"error": "sysctl data query failed"});
    }

    let actual_count = actual_len / mem::size_of::<libc::kinfo_proc>();
    procs.truncate(actual_count);

    let state_str = |s: libc::c_char| match s as u8 {
        1 => "idle",
        2 => "running",
        3 => "sleeping",
        4 => "stopped",
        5 => "zombie",
        6 => "waiting",
        7 => "locked",
        _ => "unknown",
    };

    let c_str = |buf: &[libc::c_char]| {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };

    let mut threads: Vec<serde_json::Value> = procs
        .iter()
        .map(|p| {
            serde_json::json!({
                "tid": p.ki_tid,
                "name": c_str(&p.ki_tdname),
                "state": state_str(p.ki_stat),
                // ki_wmesg is FreeBSD's wchan equivalent: short string like
                // "futex" (mutex wait), "kqread" (kqueue poll), "nanslp" (sleep).
                "wchan": c_str(&p.ki_wmesg),
            })
        })
        .collect();

    threads.sort_by_key(|t| t["tid"].as_u64().unwrap_or(0));

    serde_json::json!({
        "count": threads.len(),
        "threads": threads,
    })
}
