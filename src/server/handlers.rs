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

/// Health check endpoint. Returns 200 OK when healthy, 503 when memory-overloaded.
pub(super) async fn health(State(state): State<Arc<AppState>>) -> Response {
    let rss_mb = crate::memory_tracker::current_rss()
        .map(|b| b / 1024 / 1024)
        .unwrap_or(0);
    let active_tasks = state.active_tasks.load(std::sync::atomic::Ordering::Relaxed);
    let overloaded = rss_mb > 0 && rss_mb * 1024 * 1024 > state.max_rss_bytes;
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
    Json(serde_json::json!({
        "status": "ok",
        "rss_mb": rss_mb,
        "active_tasks": active_tasks,
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
    let mut handle = tokio::task::spawn_blocking(move || {
        let _enter = task_span.enter();
        let result = analyze_file(&path, &AnalysisOptions::default());
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
    // On timeout, the task is still running — spawn a watcher to decrement
    // and drop the temp file when it eventually completes.
    if result.is_some() {
        state
            .active_tasks
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        state.in_flight.remove(&request_id);
        drop(temp_file);
    } else {
        let active = state
            .active_tasks
            .load(std::sync::atomic::Ordering::Relaxed);
        warn!(
            filename = %filename,
            active_tasks = active,
            "Analysis timed out but blocking task still running"
        );
        let orphan_state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle.await;
            orphan_state
                .active_tasks
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            orphan_state.in_flight.remove(&request_id);
            drop(temp_file);
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
            Json(report).into_response()
        }
        Some(Ok(Err(e))) => {
            warn!(filename = %filename, elapsed_ms = elapsed_ms, "Analysis failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Analysis failed"})),
            )
                .into_response()
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
    tokio::task::block_in_place(|| crate::clear_all_thread_caches());

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

    // Still overloaded — track duration and potentially terminate
    let mut overloaded = state.overloaded_since.lock();
    let since = *overloaded.get_or_insert_with(Instant::now);
    let overloaded_secs = since.elapsed().as_secs();

    if overloaded_secs > 30 {
        tracing::error!(
            rss_mb = rss_after / 1024 / 1024,
            overloaded_secs,
            "Memory overload persisted >30s after cache clears, terminating"
        );
        std::process::exit(1);
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
    let mut handle = tokio::task::spawn_blocking(move || {
        let _enter = task_span.enter();
        let result = analyze_file(&path_owned, &AnalysisOptions::default());
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

    // Decrement active tasks on completion; on timeout, spawn a watcher to do it
    // when the blocking task eventually finishes (spawn_blocking cannot be cancelled).
    if result.is_some() {
        state
            .active_tasks
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        state.in_flight.remove(&request_id);
    } else {
        let active = state
            .active_tasks
            .load(std::sync::atomic::Ordering::Relaxed);
        warn!(
            path = %path_str,
            active_tasks = active,
            "Analysis timed out but blocking task still running"
        );
        let orphan_state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle.await;
            orphan_state
                .active_tasks
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            orphan_state.in_flight.remove(&request_id);
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
        Some(Ok(Err(e))) => {
            warn!(path = %path_str, elapsed_ms = elapsed_ms, "Analysis failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Analysis failed"})),
            )
                .into_response()
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
        tokio::task::spawn_blocking(crate::analysis_cache::cache_entry_count).await;
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

    let (rizin_total, rizin_ok, rizin_timeouts, rizin_failures) =
        crate::radare2::rizin_stats();

    Json(serde_json::json!({
        "process": {
            "rss_mb": rss_mb,
            "max_rss_mb": state.max_rss_bytes / 1024 / 1024,
            // null when not built with --features jemalloc
            "jemalloc": jemalloc,
        },
        "server": {
            "active_tasks": state.active_tasks.load(std::sync::atomic::Ordering::Relaxed),
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
            "yara_scanner_max_per_thread": 32,
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
            "archive_pool_threads": crate::analyzers::archive::analyzers::archive_pool_thread_count(),
        },
    }))
}

/// In-flight request list — shows every analysis currently running, with elapsed time.
pub(super) async fn requests(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let now = Instant::now();
    let mut entries: Vec<serde_json::Value> = state
        .in_flight
        .iter()
        .map(|e| {
            let elapsed_ms = now.duration_since(e.started_at).as_millis();
            serde_json::json!({
                "request_id": e.key(),
                "name": e.name,
                "size_bytes": e.size_bytes,
                "elapsed_ms": elapsed_ms,
            })
        })
        .collect();

    // Sort by elapsed descending so the longest-running request is first.
    entries.sort_by(|a, b| {
        b["elapsed_ms"]
            .as_u64()
            .cmp(&a["elapsed_ms"].as_u64())
    });

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
    let info = info.unwrap_or_else(|_| {
        serde_json::json!({"error": "failed to read thread info"})
    });
    Json(info)
}

fn read_thread_info() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
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

    #[cfg(not(target_os = "linux"))]
    {
        serde_json::json!({
            "note": "detailed thread info only available on Linux",
            "rayon_threads": rayon::current_num_threads(),
        })
    }
}
