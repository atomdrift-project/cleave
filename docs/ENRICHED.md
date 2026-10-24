# Enriched

`--enriched` gives paying isotope13 customers two things, in cleave and scan:

1. **The latest rules,** published the moment they clear QA. Public rules lag by up to 4 hours.
2. **Remote verdicts** (scan only): scan asks Beamline before analyzing locally and uses Beamline's verdict when it has one.

This plan adds as little as possible to what already exists:

- pulsar already publishes both rule buckets.
- The `rules` Worker already serves the private bucket to a valid token.
- dash already mints tokens, and now also issues them to devices.
- Beamline already answers lookups.

What's new is one flag, a device flow in dash, a second rules directory, and a lookup step in scan.

## Decisions

| | |
|---|---|
| Flag | A held token (`ISOTOPE13_TOKEN`, or the saved file) selects Enriched by itself, and keeps it selected until the rules Worker refuses the token: once connected, stay connected. `--enriched`, or env `ATOMDRIFT_ENRICHED=1`, insists: it asks for a token on a terminal if there is none, and a refusal is an error instead of a fall back. `ATOMDRIFT_ENRICHED=0` keeps the open-source rules whatever is held. |
| Getting a token | A device flow: the terminal shows a code, the customer approves it at `dash.isotope13.io/device`. Signing in to dash (GitHub or Google OAuth) is the OAuth step. cleave and scan have no `login` command: `--enriched` connects the computer the first time it has no token, and every later run uses what was saved. hood has `hood enrich`, because it has no per-command flag. There is no logout; delete the token file. |
| Token | A dash bearer token issued to the device, stored in `<config>/atomdrift/isotope13-api.json`. Not listed on the dashboard and not one of the org's four API tokens. No refresh token. `ISOTOPE13_TOKEN` still takes a dashboard token, for CI. |
| Refused token | Without `--enriched`: one warning that says what was wrong (unknown token, or a Community plan), and the run falls back to the open-source rules, refreshing those instead. With `--enriched`: an error that says the same and where the token came from; a saved token that is no longer recognised is replaced by connecting again, on a terminal. |
| Lapsed subscription | Installed enriched rules are left on disk. The next refresh is refused: the run falls back to the open-source rules, or fails under `--enriched`. |
| Entitlement | Every tier above Community: `supporter`, `business`, `poc`, `oem`. |
| Rules on disk | `traits-oss/` and `traits-enriched/`. The directory name records the channel. |
| scan analysis | `--analyze=auto\|local\|remote`, default `auto`. A remote verdict replaces local analysis. |
| Sent remotely | sha256 digests, and PURLs from public registries. Never a URL. |
| Lookup timing | No time budget. Lookups count against the hourly quota. |
| gauntlet | Arms `ascan` (OSS) and `ascan-enriched` (`--enriched`, auto). Freshness is part of what's measured. |
| Signing | cosign verification is still deferred (see Follow-ups). |

## Token

### Storage

One JSON file, shared by cleave and scan:

```
<dirs::config_dir()>/atomdrift/isotope13-api.json     {"token": "i13_…"}
```

- **Location.** On Linux this is `$XDG_CONFIG_HOME/atomdrift/…`. On macOS it is `~/Library/Application Support/atomdrift/…`, the same root cleave already uses for traits.
- **Writing.** cleave writes the file to a temp path and renames it into place. The file is mode `0600` and its directory `0700`.
- **Reading.** On Unix, a file that anyone other than the owner can read or write is refused, the way ssh refuses a key with loose permissions. The error names the `chmod` that fixes it.
- **CI.** `ISOTOPE13_TOKEN` takes precedence over the file. That's how CI supplies a token minted on the dashboard, with no file and no terminal.
- **`~/.tok/isotope13` is no longer read.** `~/.tok` is for internal service tokens.
- **Only the token is stored.** The server decides tier and validity, and a cached copy of either would be one more thing that could be stale.

### Getting one

```
$ scan --enriched ./project

⚛️  isotope¹³ Enriched — the latest atomdrift rules, the moment they clear QA.

   Approve this computer in your browser:  https://dash.isotope13.io/device?code=NG8N-JZRS

   ⠋ Waiting for approval…
```

The browser opens on that link by itself where there is one (`open` on macOS, `xdg-open` under a display on Linux, `start` on Windows); over SSH the link is there to open from anything. The page shows the code large with one Approve button. The last line is redrawn in place, and once the token is checked it becomes:

```
   ✓ Connected on the Business plan.
   Token saved to ~/.config/atomdrift/isotope13-api.json
```

- **One implementation, in cleave.** `cleave::rule_update::sign_in` (and `enrich`, which `hood enrich` calls) holds the whole flow; scan, hood and postdoc inherit it.
- **Asked once, up front.** cleave and scan call `sign_in` before anything downloads rules, so connecting happens at the start of the run, not inside the first download that needs a token — and not again inside the second.
- **Terminals only.** The welcome and link appear only when stdin and stderr are both terminals. Without one it fails instead: `isotope13 Enriched needs a token: set ISOTOPE13_TOKEN, or run with --enriched on a terminal to connect this computer (hood: \`hood enrich\`)`.
- **Validated before it's trusted.** The issued token is checked by fetching the enriched manifest (see "Token validity" below). dash writes it to KV a moment before handing it over, KV takes up to a minute to reach every edge, and the rules Worker caches a miss for another minute, so a check that does not recognise a just-issued token is retried for 150 seconds before it is believed. The progress line reads "Approved. Connecting…" meanwhile.
- **A Community org keeps its token.** It is real, so it is saved, and the run fails saying the plan gets the public rules and where to upgrade. The upgrade reaches the same token; there is no second connection.
- **A saved token that is no longer recognised** (revoked, or evicted) is replaced by connecting again, on a terminal; off one, the error names the file.
- **The opener is resolved to an absolute path** (`filefacts::tools::resolve`), never looked up on a PATH that might name the working directory.

### The device flow (dash)

| route | caller | does |
| --- | --- | --- |
| `POST /device/code` | CLI | `{label}` → `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}` |
| `GET/POST /device` | browser, signed in | the page the code is typed into; approving mints the token |
| `POST /device/token` | CLI | `{device_code}` → `202` pending, `200 {token, tier}` once, `410` gone |

- **Two codes.** The one a person reads is 8 characters (`XXXX-XXXX`, case and dash optional when typed). The one the CLI polls with is 32 characters (160 bits) and never shown. Both expire in 10 minutes.
- **The code travels in the link** (`verification_uri_complete`), so the page shows it large above one Approve button, with "Enter it yourself" underneath for a code that is not the one on screen. Signing in from that link lands back on it, code included; sign-in may be sent to `/device` with or without a code and nowhere else.
- **Single use, both halves.** A code approves once; the token leaves KV with the first poll that collects it.
- **A device's token is not the dashboard's.** It is stored on the org as `devices`, not `tokens`: not shown, not counted against the four, and cannot be read back from dash. Its `tok:` entry carries `device: true`; every reader treats it like any other token today. A tier change rewrites it with the rest. An org holds at most 32; the oldest is revoked to make room.
- **CSRF.** The two JSON routes are unauthenticated and called by a CLI, so they sit before dash's Origin check. Approving is a browser action behind a session and the check, like every other change.
- **Phishing,** the attack device codes are known for (an attacker starts a flow and sends a victim the link), is the trade-off of carrying the code in the link. GitHub makes you type it; Google and Tailscale carry it. What stands in the way here: the page shows the code large and asks "Is this the code your terminal is showing?", says "Only approve a code you asked for yourself, just now", names the plan the device will join, and still needs a click. A Community org is told before approving that the device gets the public rules.
- **The label** is `<tool> on <os>`, nothing that names the person or the machine.

### Why not refresh tokens

- **Refresh tokens add little here.** A refresh token kept next to the access token is stolen along with it. Rotation would also race between scan's worker pool and between gauntlet's two arms, with each refresh invalidating the other's token.
- **What already limits a stolen token:**
  - Each token is per device, named by the person who mints it, and shows its last use in dash.
  - Revoking one takes effect within 60 seconds.
  - Logs carry only Beamline's fingerprint (the first 16 hex characters of the token's SHA-256), never the token itself.

  The place where short-lived credentials really matter is CI (see Follow-ups).

### Where the token may go

- **Only two hosts.** The token is sent only to `updates.isotope13.ai` and `api.isotope13.ai`, over HTTPS, in the `Authorization` header.
- **Fixed URLs.** Both base URLs are constants, with no override in any build: an override would let any CI step redirect rules and token to itself. (hood keeps its `HOOD_BEAMLINE_URL`, but sends the token only to `https://api.isotope13.ai`.)
- **No redirects.** The enriched client is built with `redirect::Policy::none()`, so a redirect can never carry the token anywhere else.
- **Never on the fetch client.** scan's dependency fetch client never carries the token.

## Rules

### Directories

```
<data>/atomdrift/cleave/traits-oss/        public bucket, updates.atomdrift.org (no token)
<data>/atomdrift/cleave/traits-enriched/   private bucket, updates.isotope13.ai (token)
```

- **Selection.** `--enriched` selects `traits-enriched`. `--traits-dir` and `CLEAVE_TRAITS_DIR` still override both.
- **Which one am I on?** Every tool's `version` (`cleave version`, `atomscan version`, `hood version`, `postdoc version`) names the edition in use, read from the directory that resolved rather than the flag: `isotope¹³ Enriched`, `open source`, or `checkout` with its path. cleave's terminal banner says the same. `atomscan --format json version` reports it as `traits_channel`: `enriched`, `oss` or `checkout`.
- **Migration.** On first run, an existing `traits/` is renamed to `traits-oss/` if `traits-oss/` doesn't exist yet. The rename is a single atomic step on the same filesystem, and it means a host that is offline right after an upgrade still has rules.
- **scan stops hard-coding the path** (`scan/src/traits_repo.rs:25`). cleave exports `traits_repo::installed_dir(enriched: bool)` and scan calls it.

### Token validity

The token is checked when rules are downloaded, not when files are scanned.

- **Analysis never contacts the rules service.** An installed `traits-enriched/` loads as-is.
- **The check is a header, not a status code.**
  - Each enriched manifest fetch sends the token.
  - The `rules` Worker answers an unknown or Community key with *public* bytes and a 200, so old clients keep working.
  - cleave therefore requires `x-isotope13-channel: fresh` on the manifest, and treats anything else as a refusal.
  - The Worker also sends `x-isotope13-tier` for a token it recognises, so the refusal says which it was: `isotope13 token 8f2d… is on the free plan, which gets the public rules; upgrade at …`, or that it is not recognised. That message is written for where the token came from: `ISOTOPE13_TOKEN` ("check it holds the whole token"), the saved file ("revoked, or the computer was disconnected"), or a device flow just now.
- **Network failures stay quiet, refusals don't.** If scan's daily auto-update can't reach the network, it stays quiet as it does today, and the installed rules keep working. A refusal is a fall back to the open-source rules with one warning (`cleave::rule_update::refresh`), or an error under `--enriched`, which can't be honoured. A first install that fails for any reason falls back the same way, rather than scanning with no rules; under `--enriched` it is the error it always was.
- **Code removed.** The current 401 fallback in `fetch_manifest` (`src/rule_update.rs:306`) can never fire, so it goes, along with the module docs that describe it.

### rules Worker

`FRESH_TIERS` becomes `{supporter, business, poc, oem}` (`iso13/rules/rules.js:46`, plus the README table). Today it is `{business, oem}`, which already disagrees with dash's `TIERS`: that table marks Early Supporter as `fresh`.

The set is written out explicitly so that an unknown tier fails closed.

## scan: `--analyze`

| mode | without `--enriched` | with `--enriched` |
|---|---|---|
| `local` | today's behaviour | `traits-enriched` rules, no lookups |
| `auto` (default) | same as `local`: no new network traffic for OSS users | look up first, analyze locally on a miss |
| `remote` | error: requires `--enriched` | everything goes to `/v1/analyze`; local files are uploaded |

Env `SCAN_ANALYZE`. The `--help` text says what leaves the machine. It also says that `local` is the reproducible mode: a remote verdict depends on what the server knew at the time.

### `auto`

1. **Dependencies.** These are looked up before anything is fetched, in batches of up to 50 per `GET /v1/lookup`. When the lockfile records a sha256 (Cargo, PyPI and uv do), scan sends it alongside the PURL, and Beamline refuses an answer that describes different bytes. A hit with `status: analyzed` uses the remote verdict, so scan skips both the download and the analysis. Anything else takes the existing fetch-and-analyze path (`scan/src/fetch.rs`). This is where most of the benefit is.
2. **Local files at or over scan's small-job threshold** (1 MiB, `small_job_max_bytes`).
   - These go through a streaming hash pass with bounded memory, a batched sha256 lookup, and then analysis of the misses only.
   - Below the threshold, analyzing locally is cheaper than asking, and those files are mostly unique source code that no corpus has seen. This reuses an existing threshold rather than adding a new setting.
   - Reading a miss twice costs page cache, not RAM: there is never more than one copy of a file in memory.
3. **URL inputs** are fetched as they are today. The bytes are then looked up by sha256. The URL itself is never sent.

**Every answer is checked against the question.** An answer whose `sha256` differs from the digest that was asked, or whose PURL coordinate differs from the one sent, is treated as a miss and logged.

**Failure rule.** Lookups go through scan's existing `corpus_precheck`: the same batched `/v1/lookup` client, circuit breaker, and fail-open rule hopper's fleet lookups use, armed against isotope13 with the token.
- Any failure (`5xx`, a connection failure, a malformed body) means that batch is analyzed locally. Five transport failures in a row pause lookups for five minutes, with one log line.
- A `401`, `403` or `429` pauses them at once. A revoked token is an *error* only at the rules gate (`update-rules`, the daily auto-update, first install); during a scan it costs the speed-up, never the answer.
- Falling back to local analysis is always safe, because local analysis is a complete analysis. The cost of falling back is time, never correctness.
- A clean verdict older than 30 days (`SCAN_CORPUS_MAX_AGE_DAYS`) is analyzed again rather than trusted; hostile and suspicious verdicts are adopted at any age. This settles the stale-benign open point on the client, reusing the precheck's existing bound.

The client has a 4-second connect timeout and a 15-second per-lookup ceiling, and no other time budget.

### `remote`

- PURL inputs go to `POST /v1/analyze?purl=…`.
- Local files are uploaded as the raw request body, one at a time.
- A file over Beamline's 16 MiB upload cap is an error that names the file. Analyzing it locally without saying so would contradict an explicit `remote`.

### What may be sent

| key | rule |
|---|---|
| sha256 | always |
| PURL | any package on a mainstream public registry — npm (scoped included), PyPI, crates.io, RubyGems, NuGet, Go, Maven, Packagist, Hex, pub.dev, CocoaPods, conda, CRAN, Hackage — unless a `repository_url` qualifier names a different registry (`scan::remote::public_purl`). `github`, `generic`, and unknown types are judged by digest. |

A PURL names a package, so it says what a project depends on; that is accepted for mainstream registries. A `repository_url` is how a coordinate says it came from a private mirror, which is the one case never sent.

### Output

- A remote verdict is written as a `"source": "remote"` record, the way a bloom decision is already written as `"source": "bloom"`. Local results are unchanged, so the main envelope's schema doesn't move.
- Remote records carry `sha256`, `fires_at`, `analyzed_at`, `engine_version` and (for packages) `purl`.
- Remote results have at most 3 findings, which is Beamline's cap.
- Severity and exit codes mean the same thing in both cases.
- The change is documented in `scan/docs/JSON.md`.
- The response types come from `scan/src/lookup.rs`, which already serves this format, rather than a second copy.

## Beamline

`GET /v1/lookup` accepts a repeated `sha256`, just as it accepts a repeated `purl`. Both count toward the same cap of 50, and a repeated key answers with a list.

Without this, a local scan costs one request per file, and 5,000 files would exhaust a Supporter org's 4,096 requests per hour.

A batch that misses Beamline's cache is split into one share per live worker (at most 4), and the shares are asked in parallel. Each share has its own failover. A worker that answers fewer rows than it was asked is tried elsewhere, as a 404 is, so a server that keeps only the last `sha256` never stands in for the batch. Every origin behind `SCAN_URL` (scan serve and postdoc serve) therefore takes a repeated `sha256`.

## hood

hood runs as a shim in front of package managers and passes their arguments straight through, so it has no per-command flag to put `--enriched` on. Its opt-in is a one-time `hood enrich` instead. There is no way to undo it but deleting the token file.

- **`hood enrich`** runs the same ask-and-validate function as `--enriched` does in cleave and scan (`cleave::rule_update::enrich`), and writes the same shared token file. Once hood is enriched, `scan --enriched` and `cleave --enriched` find the token and don't ask.
- **Logged in means enriched.** hood sends the token to Beamline, and its local analysis uses `traits-enriched`, refreshed at most once a day like its Bloom filters. hood's existing Beamline client (PURLs and hashes only, redirects rejected, 30-day cache) is otherwise unchanged.
- **The token comes from `ISOTOPE13_TOKEN`, then the file.** `HOOD_BEAMLINE_TOKEN` is removed (hood is experimental and has no changelog; the README's settings table says so).
- **A refused token is a warning, not a failure.** hood warns at most once a day (`run hood enrich`), keeps the installed enriched rules, and keeps doing full local analysis. A billing problem never blocks a developer's install. This is the one place enriched doesn't error, because hood is enforcing a security check, not producing a report.

## postdoc

postdoc replaces `atomscan serve` and `atomscan worker`, and is what isotope13's remote analysis runs on. `--enriched` there means the Enriched rules and nothing else: it never arms isotope13 lookups (that would be a loop), and `--analyze=remote` is refused.

- **Default:** unlike cleave and scan, postdoc runs Enriched whenever the host holds a token (`ISOTOPE13_TOKEN` or the saved file), since a fleet host with one has no other reason to. An explicit `ATOMDRIFT_ENRICHED=0` (or `=1`) overrides that; a held token is then used exactly as `--enriched` would use it.
- **Startup:** a missing or refused token stops the daemon from starting (`scan::refresh_rules_at_startup` now returns that one failure; every other update failure is still a warning).
- **Renewal:** a token refused later is logged at error level on each renewal, and the installed rules go on serving. A fleet never goes down over a key.
- **Idle worker:** the server forwards `--enriched` to the companion worker it spawns, as it already forwards `--traits-dir`.
- **Deploy:** `ENRICHED=1` adds the flag and installs `~/.tok/isotope13` as the service's `<state>/.config/atomdrift/isotope13-api.json` (0600). It is saved in the deploy manifest, so rollouts keep it.

## gauntlet

- **`ascan`** is unchanged: no flag, so it uses OSS rules, and `auto` behaves as `local`.
- **`ascan-enriched`** is the same binary with `--enriched`, so `auto`, and reads its token from `ISOTOPE13_TOKEN`. Without a token, the arm is skipped with one warning at startup. It never uploads to hopper: hopper is what isotope13 answers from, so its own results written there would come back to it as remote verdicts.
- **Each arm updates its own rules before the run.** `battle.json` records each arm's channel, traits and models commits and dates (from `atomscan --format json version`, which now reports `traits_date`, `models_date` and `traits_channel`), so a freshness gap shows up in the results instead of hiding.
- **`ascan-enriched` also records its remote-hit rate,** read from `source`. Under `auto`, a cohort sample Beamline has already seen is answered from that stored verdict. The hit rate keeps "the product" and "the rules" separable.

## Logging

Every log line is structured and uses the same keys in cleave and scan. The token never appears in a log; its fingerprint (`tid`) does.

| event | fields |
|---|---|
| `enriched.token` | `source` (`env`, `file`, `prompt`), `outcome` (`ok`, `refused`, `missing`, `bad_perms`) |
| `enriched.rules` | `channel`, `commit`, `date`, `outcome` (`installed`, `current`, `refused`, `network`) |
| `remote.lookup` | `keys`, `hits`, `misses`, `mismatched`, `status`, `ms` |
| `remote.disabled` | `reason`, `status`, `retry_after` |
| `remote.withheld` | `count`, `reason` (`private_registry`, `unknown_source`) |

## Work, in order

Steps 1 and 2 are independent. Step 3 needs neither of them to start.

1. **rules:** `FRESH_TIERS`, README table, test.
2. **Beamline:** repeated `sha256` on `/v1/lookup`, a batch split across the workers, API.md, tests. It deploys after every origin behind `SCAN_URL` takes a repeated `sha256` (step 7 for postdoc).
3. **cleave:**
   - A new `src/enriched.rs` covering the token (env, then file, with the permission check), the prompt, and the HTTP client (fixed base URLs, no redirects).
   - The `--enriched` flag and `ATOMDRIFT_ENRICHED`.
   - `traits-oss` and `traits-enriched`, plus the rename of the old directory.
   - The `fresh` header check.
   - Deleting the 401 fallback and the `~/.tok` read.
4. **scan:**
   - Bump the cleave pin.
   - Handle `--enriched` in `prepare_runtime_env` and `auto_update`.
   - Add `--analyze`, the PURL eligibility rule, the batched lookup with its answer check, upload for `remote`, and the `source` output field.
5. **gauntlet:** the `ascan-enriched` arm, plus per-arm rule metadata and the remote-hit rate.
6. **hood:** bump the scan pin, add `hood enrich`, read the token from `ISOTOPE13_TOKEN` or the file, and refresh `traits-enriched` daily.
7. **postdoc:** bump the scan pin; repeated `sha256` on its own `/v1/lookup`; `--enriched` (or a held token) selects the rules, forwarded to the idle worker; `ENRICHED=1` in deploy.

pulsar and dash need no changes.

## Tests

- **cleave:**
  - Token precedence, the file-permission refusal, and missing versus refused versus non-interactive tokens.
  - The `fresh` header is accepted; the `public` header is refused.
  - Redirects are not followed.
  - The `traits/` → `traits-oss/` rename.
  - Against `node iso13/rules/local.js` with `RULES_TOKENS`, using one `supporter` key and one `free` key.
- **scan:**
  - The PURL eligibility table: `repository_url`, a private resolved source, an unknown source.
  - Batching at 50.
  - A mismatched answer counts as a miss.
  - Failures: `401` is an error; `429`, `5xx` and a connection failure fall back and switch lookups off.
  - `auto` without `--enriched` sends zero requests.
  - Files below 1 MiB are never looked up.
  - A `remote` upload over 16 MiB is an error.
- **Beamline:** repeated `sha256`, the shared cap of 50, and list ordering; a batch split across two workers, a short answer retried elsewhere, and a share nobody answers coming back `unavailable` by digest.

## Open points

- **How old a benign verdict may be.** Beamline should say how old a *benign* answer it will serve can be, relative to the current rules. Under `auto`, a stale benign verdict means local analysis that would have caught something never runs. The server knows which ruleset produced each verdict, so the policy belongs there and the client stays simple.
- **The `poc` tier.** It exists in Beamline but not in dash's `TIERS`. It is included in `FRESH_TIERS` so that a `poc` token, if one is ever minted, gets fresh rules.

## Follow-ups (not v1)

- **Verify the manifest signature.** The `rules` Worker already serves `versions.toml.sigstore.json`. `sigstore-spike` showed that sigstore 0.14 can verify it offline against a pinned identity. Because the manifest carries each bundle's sha256, one check on the manifest covers everything downloaded. Without it, whoever controls the bucket or either Worker controls what every customer detects. The cost is the sigstore crate's dependency tree.
- **Short-lived tokens for CI.** Exchange a GitHub Actions OIDC token at dash for a short-lived isotope13 token bound to the repository, so no long-lived token has to live in CI secrets. Leaked CI secrets are the most common way supply-chain credentials escape. The client treats the token as opaque, so this needs only a new place to get a token from.
