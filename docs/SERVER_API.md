# Cleave Server API

`cleave serve` is an HTTP daemon that takes a file and returns an
`AnalysisReport`. It binds to loopback by default. It has no
authentication. Treat it as a local service and put a reverse proxy
in front of it if anything else needs to reach it.

For the response schema, see [JSON.md](JSON.md). For the library and
CLI, see `cleave --help`. For the Rust library, see
[RUST_API.md](RUST_API.md).

## Running the server

    cleave serve

The defaults are deliberate. Override them only when you have a reason.

| Flag                            | Default            | Meaning                                                              |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| `--bind`                        | `127.0.0.1:8080`   | Listen address.                                                      |
| `--qps`                         | `100`              | Max requests per second per client IP.                               |
| `--max-size-mb`                 | `100`              | Per-request upload limit.                                            |
| `--max-rss-gb`                  | 25% of system RAM  | RSS ceiling. New requests get 503 once exceeded.                     |
| `--dangerous-local-file-paths`  | none               | Comma-separated roots permitted by `/analyze-path`. Off by default.  |
| `--extract-dir`                 | none               | Where cleave writes archive members. Implicitly added to allowed roots. |

Concurrency is sized automatically: `2 × available_parallelism()`. New
requests past that limit get 503; there is no queue.

Environment variables read at startup:

| Variable                  | Effect                                                       |
| ------------------------- | ------------------------------------------------------------ |
| `CLEAVE_TRAITS_DIR`       | Traits directory. Required.                                  |
| `CLEAVE_RAYON_THREADS`    | Rayon pool size. Default is system parallelism.              |
| `CLEAVE_MAX_RSS_GB`       | RSS ceiling. `--max-rss-gb` overrides.                       |
| `CLEAVE_LOGS_DIR`         | Write tracing logs to this directory instead of stderr.      |

The listener binds before YARA rules and the capability mapper are
loaded. While loading, requests block on the resource init (~27 s on a
cold start). Health flips to `ok` once resources are warm.

## Endpoints

### `POST /analyze`

Multipart upload. One part named `file`. The filename is sanitised
(control chars dropped, truncated to 255 bytes) and copied to a private
temp directory so cleave sees a plausible extension.

    curl -s -F file=@/bin/ls http://127.0.0.1:8080/analyze | jq .

Returns 200 with an `AnalysisReport`. 413 if the body exceeds
`--max-size-mb`, 415 for unsupported types, 422 for truncated or
malformed input, 429 when the per-IP rate limit is exceeded, 503 if
the server is overloaded or saturated.

### `POST /analyze-path`

JSON body: `{"path": "/absolute/path"}`. Disabled unless
`--dangerous-local-file-paths` is set. The path is canonicalised
before it is compared against the allowed roots, so symlinks cannot
escape. Without allowed roots, every request returns 403. Relative
paths return 400; missing files return 404.

    curl -s -H 'content-type: application/json' \
      -d '{"path":"/usr/bin/ls"}' \
      http://127.0.0.1:8080/analyze-path | jq .

Same response envelope as `/analyze`.

### `GET /_/health`

Liveness and load. 200 when ready, 503 when memory-overloaded or the
thread pool is saturated.

    {
      "status": "ok",
      "rss_mb": 312,
      "active_tasks": 1,
      "rayon_threads": 8
    }

`status` is one of `ok`, `degraded`. A `degraded` response also carries
`reason` (`memory_pressure` or `thread_pool_saturated`) and the
relevant ceiling.

### `POST /_/reload`

Reread traits from `CLEAVE_TRAITS_DIR` and atomically hot-swap the
capability mapper. Returns the new trait and composite counts plus
elapsed time. 409 if another reload is already in progress, 422 if the
new trait set fails validation (previous rules retained).

### `GET /_/memory`

Allocator and cache diagnostics: RSS, jemalloc counters (when built
with `--features jemalloc`), SQLite analysis cache size, bytes-regex
cache size, capability mapper stats, rizin success / timeout / failure
counters, rayon thread count.

### `GET /_/requests`

In-flight analyses with elapsed time, size, and phase. Useful for
spotting stuck requests before the watchdog fires.

### `GET /_/threads`

Per-thread state. Linux exposes `wchan` and context-switch counters;
FreeBSD reports the rayon thread count; other platforms return an
error.

## Status codes

| Code | Cause                                                                   |
| ---- | ----------------------------------------------------------------------- |
| 400  | Malformed request body or relative path on `/analyze-path`.             |
| 403  | `/analyze-path` disabled, or path outside the allowed roots.            |
| 404  | `/analyze-path` target does not exist or is unreadable.                 |
| 409  | `/_/reload` while another reload is in progress.                        |
| 413  | Body exceeds `--max-size-mb`.                                           |
| 415  | Unsupported file, archive, or compression format.                       |
| 422  | Truncated, encrypted-without-password, depth or count limit exceeded.   |
| 429  | Per-IP `--qps` rate limit exceeded.                                     |
| 500  | Internal error.                                                         |
| 503  | Memory pressure or thread pool saturated.                               |

Errors share a single shape:

    { "error": "string", "detail": "optional chain" }

## Security

The server is built for trusted networks. The defaults reflect that.

- **Bind is loopback.** Do not change `--bind` without thinking about
  what else can now reach it.
- **No authentication. No TLS.** If the server is reachable from
  anywhere but localhost, put a reverse proxy in front of it that does
  both.
- **`/analyze-path` is off by default.** Enable it only with an
  explicit allow-list via `--dangerous-local-file-paths`. The path is
  `canonicalize()`d before the prefix check, so symlinks cannot point
  outside the allowed roots.
- **Filenames are sanitised.** Control characters dropped, truncated to
  255 bytes. The original name is never used on disk.
- **Body size is capped** by `--max-size-mb` and enforced during
  streaming, not after.
- **RSS is capped.** New requests get 503 once the process exceeds
  the limit. The default is 25% of system RAM; `--max-rss-gb`
  overrides.
- **Concurrency is a hard semaphore.** When `2 × ncpu` slots are full,
  new requests get 503 immediately. There is no queue.
- **Rate limiting is per-IP.** `--qps` caps requests per second per
  client IP; the limiter tracks up to 50,000 distinct IPs.
- **Static analysis only.** No untrusted code is executed. Cleave
  runs rizin in an isolated process group; if it gets stuck, the
  watchdog kills the group, not just the parent.

## Example session

    $ cleave serve --bind 127.0.0.1:8080
    $ curl -s http://127.0.0.1:8080/_/health | jq -r .status
    ok
    $ curl -s -F file=@/bin/ls http://127.0.0.1:8080/analyze \
        | jq '.files[0] | {sha256, formula, criticality}'
