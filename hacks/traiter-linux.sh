#!/bin/sh
# traiter-linux.sh - Install the 30-minute cleave trait-publish timer.
#
# The trait bundles + versions.toml manifest are rebuilt from the cleave-traits
# source of truth and uploaded to R2 every 30 minutes. This installs that cycle as
# a systemd timer (cleave-traiter.timer -> cleave-traiter.service, Type=oneshot)
# running `make publish-traits-cron`. It is the traits analog of scan's
# scripts/worker/bloomer-linux.sh (the "bloom crontab").
#
# It runs as a DEDICATED `traiter` system user, so the publishing credential (the
# R2 token) is isolated from anything else on the host. Everything lives under one
# state tree, /var/lib/traiter:
#
#   /var/lib/traiter               HOME + StateDirectory. Holds the R2 rclone
#                                  config, the Rust/Go toolchains, and build caches
#   /var/lib/traiter/cleave-src    cleave source checkout (WorkingDirectory): the
#                                  Makefile + tools/manifest-gen the cycle runs
#   /var/lib/traiter/cleave-traits cleave-traits checkout (TRAITS): the trait
#                                  source of truth, fast-forwarded each cycle
#
# UNSIGNED by default. `make publish-traits-cron` runs gen-manifest WITHOUT SIGN=1,
# so no cosign identity is needed and nothing is written to the public Rekor
# transparency log. The published versions.toml has NO signature bundle, so any
# client that requires a signature will NOT apply the update — auto-update stays
# effectively disabled until you wire up signing. Because there's no signing and
# both checkouts are pulled read-only, the ONLY secret this host needs is the R2
# rclone config; there is no push key and no database password (unlike the bloomer).
#
# To enable automated signing later (keyless cosign as the releaser service
# account), pick one of:
#   * Run this timer on a GCE VM whose attached service account IS the releaser SA.
#     cosign's ambient GCP provider mints the OIDC token from the metadata server
#     automatically — nothing else to configure.
#   * On any Linux box, give `traiter` a base Google credential that can impersonate
#     the releaser SA (roles/iam.serviceAccountTokenCreator), then have the cycle
#     export a fresh token before signing:
#       SIGSTORE_ID_TOKEN=$(gcloud auth print-identity-token \
#         --impersonate-service-account=releaser@PROJECT.iam.gserviceaccount.com \
#         --audiences=sigstore --include-email)
#     cosign reads SIGSTORE_ID_TOKEN and signs keyless as that identity.
# Then switch the gen-manifest line in `publish-traits-cron` to SIGN=1 IDENTITY=...
# and add a `check-manifest IDENTITY=...` gate.
#
# Re-runnable: idempotent. Re-running refreshes the source checkout to origin/main,
# re-asserts the units, and reloads the timer.
#
# Secrets it CANNOT create for you (it checks and reports what is missing, but
# still installs the timer so you can drop them in afterwards):
#   ~traiter/.config/rclone/rclone.conf   rclone remote backing $(R2_REMOTE) (R2)
#
# Usage: ./hacks/traiter-linux.sh                (run from the repository root)
#
# Environment overrides:
#   CLEAVE_REMOTE  git URL of the cleave repo to clone         (default: https://codeberg.org/atomdrift/cleave.git)
#   TRAITS_REMOTE  git URL of the cleave-traits repo to clone  (default: https://codeberg.org/atomdrift/cleave-traits.git)
#   ON_CALENDAR    systemd OnCalendar= cadence                 (default: *:0/30, every 30 min)
#   GO_VERSION     Go toolchain to fetch if none is installed  (default: 1.26.4)
#   VERSIONS       versions to compat-test, including HEAD      (default: 3)
#   RUN_NOW=1      kick one cycle immediately after install (otherwise wait for the timer)

set -eu

SERVICE_USER=traiter
SERVICE_NAME=cleave-traiter
STATE_HOME=/var/lib/traiter
CLEAVE_SRC=${STATE_HOME}/cleave-src
TRAITS_DIR=${STATE_HOME}/cleave-traits
DIST_DIR=${STATE_HOME}/dist
STAMP_FILE=${STATE_HOME}/publish-traits.stamp
CARGO_HOME_DIR=${STATE_HOME}/.cargo
RUSTUP_HOME_DIR=${STATE_HOME}/.rustup
GOROOT_DIR=${STATE_HOME}/goroot

SERVICE_FILE=/etc/systemd/system/${SERVICE_NAME}.service
TIMER_FILE=/etc/systemd/system/${SERVICE_NAME}.timer

# Both checkouts are pulled read-only (never pushed), so plain HTTP — no deploy key.
CLEAVE_REMOTE="${CLEAVE_REMOTE:-https://codeberg.org/atomdrift/cleave.git}"
TRAITS_REMOTE="${TRAITS_REMOTE:-https://codeberg.org/atomdrift/cleave-traits.git}"
ON_CALENDAR="${ON_CALENDAR:-*:0/30}"
GO_VERSION="${GO_VERSION:-1.26.4}"
VERSIONS="${VERSIONS:-3}"
RUN_NOW="${RUN_NOW:-}"

die() { echo "error: $*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

# Run a command as the traiter user with its HOME/toolchain environment, so
# cargo/go/git/rclone resolve their config and caches under $STATE_HOME. GOTOOLCHAIN
# is pinned local so `go build` never tries to fetch a toolchain over the network.
RUN_PATH="${CARGO_HOME_DIR}/bin:${GOROOT_DIR}/bin:/usr/local/bin:/usr/bin:/bin"
as_traiter() {
    $SUDO -u "$SERVICE_USER" env -i \
        HOME="$STATE_HOME" \
        CARGO_HOME="$CARGO_HOME_DIR" RUSTUP_HOME="$RUSTUP_HOME_DIR" \
        GOTOOLCHAIN=local \
        PATH="$RUN_PATH" \
        "$@"
}

# --- Preconditions -----------------------------------------------------------

[ -f Makefile ]                      || die "run from the repository root"
[ "$(uname -s)" = "Linux" ]          || die "this script is for Linux"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found (systemd required)"
command -v git       >/dev/null 2>&1 || die "git required"

# Privilege escalation: prefer doas, fall back to sudo.
if   command -v doas >/dev/null 2>&1; then SUDO=doas
elif command -v sudo >/dev/null 2>&1; then SUDO=sudo
else die "need doas or sudo"
fi
MAKE_BIN=$(command -v make) || die "make not found"

# --- Service user + dir layout ----------------------------------------------

if ! getent passwd "${SERVICE_USER}" >/dev/null; then
    log "Creating service user '${SERVICE_USER}'"
    $SUDO useradd --system --home-dir "${STATE_HOME}" --no-create-home \
                 --shell /usr/sbin/nologin \
                 --comment "Cleave trait publisher" "${SERVICE_USER}"
fi

# Pre-create the state tree. systemd re-asserts /var/lib/traiter via
# StateDirectory=traiter on each start, but creating it now lets us seed the
# checkouts and run a warm build before the first timer tick.
$SUDO install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_HOME}"
$SUDO install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${CLEAVE_SRC}"

# --- Cleave source checkout --------------------------------------------------

# cleave-src is a shallow read-only checkout of the canonical cleave repo. The
# timer fetches origin/main fresh before each build (ExecStartPre below), so
# deployed code tracks the repo without a redeploy. Seed it once here (init+fetch
# over the existing dir keeps any target/ build cache), then refresh to the tip.
log "Setting up cleave source checkout at ${CLEAVE_SRC} (tracking ${CLEAVE_REMOTE})"
if ! as_traiter git -C "${CLEAVE_SRC}" rev-parse --git-dir >/dev/null 2>&1; then
    as_traiter git -C "${CLEAVE_SRC}" init -q -b main
    as_traiter git -C "${CLEAVE_SRC}" remote add origin "${CLEAVE_REMOTE}"
fi
as_traiter git -C "${CLEAVE_SRC}" remote set-url origin "${CLEAVE_REMOTE}"
# --tags so the release tags (v<n>) land locally — publish-traits-cron keys the
# manifest by them and gates on their set, and manifest-gen `git archive`s each.
as_traiter git -C "${CLEAVE_SRC}" fetch -q --tags --depth=1 origin main \
    || die "cannot fetch ${CLEAVE_REMOTE} as ${SERVICE_USER}"
as_traiter git -C "${CLEAVE_SRC}" reset --hard -q FETCH_HEAD

# --- cleave-traits checkout (the source of truth the cycle publishes) --------

# Pulled --ff-only each cycle by `make publish-traits-cron`; needs a real tracking
# branch, so a full clone (not a detached shallow reset like cleave-src above).
if [ -d "${TRAITS_DIR}/.git" ]; then
    log "cleave-traits checkout present at ${TRAITS_DIR}; normalizing to origin/main"
    as_traiter git -C "${TRAITS_DIR}" remote set-url origin "${TRAITS_REMOTE}" 2>/dev/null \
        || as_traiter git -C "${TRAITS_DIR}" remote add origin "${TRAITS_REMOTE}"
    as_traiter git -C "${TRAITS_DIR}" fetch -q origin main \
        || log "WARNING: could not fetch ${TRAITS_REMOTE}; the cycle will retry"
    as_traiter git -C "${TRAITS_DIR}" reset --hard -q origin/main 2>/dev/null || true
else
    if [ -e "${TRAITS_DIR}" ]; then
        log "Clearing stale non-git ${TRAITS_DIR} before clone"
        as_traiter rm -rf "${TRAITS_DIR}"
    fi
    log "Cloning cleave-traits into ${TRAITS_DIR} (${TRAITS_REMOTE})"
    as_traiter git clone -q "${TRAITS_REMOTE}" "${TRAITS_DIR}" \
        || log "WARNING: could not clone ${TRAITS_REMOTE}; clone it by hand or re-run this script"
fi

# --- Rust toolchain (traiter-owned) -----------------------------------------

if as_traiter sh -c 'command -v cargo >/dev/null 2>&1'; then
    log "Rust toolchain already present for ${SERVICE_USER}"
else
    command -v curl >/dev/null 2>&1 || die "curl required to install the Rust toolchain"
    log "Installing Rust toolchain for ${SERVICE_USER} (into ${CARGO_HOME_DIR})"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | as_traiter sh -s -- -y --no-modify-path --default-toolchain stable \
        || die "rustup install failed"
fi

# --- Go toolchain (for tools/manifest-gen; stdlib-only, no module fetch) -----

if as_traiter sh -c 'command -v go >/dev/null 2>&1'; then
    log "Go toolchain already present for ${SERVICE_USER} ($(as_traiter go env GOVERSION 2>/dev/null || echo '?'))"
else
    command -v curl >/dev/null 2>&1 || die "curl required to install the Go toolchain"
    case "$(uname -m)" in
        x86_64)        goarch=amd64 ;;
        aarch64|arm64) goarch=arm64 ;;
        *)             goarch= ;;
    esac
    if [ -z "$goarch" ]; then
        log "WARNING: unknown arch $(uname -m); install Go >= ${GO_VERSION} into ${GOROOT_DIR} by hand"
    else
        log "Installing Go ${GO_VERSION} for ${SERVICE_USER} (into ${GOROOT_DIR})"
        as_traiter install -d -m 0755 "${GOROOT_DIR}"
        curl --proto '=https' --tlsv1.2 -sSfL \
            "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
            | as_traiter tar -C "${GOROOT_DIR}" --strip-components=1 -xzf - \
            || log "WARNING: Go install failed; the cycle needs go for manifest-gen"
    fi
fi

# --- Warm build (surface toolchain errors before the first timer tick) ------

log "Warm-building cleave + manifest-gen as ${SERVICE_USER}"
as_traiter sh -c "cd '${CLEAVE_SRC}' && cargo build --release" \
    || log "WARNING: cleave warm build failed; the timer will retry, but check the toolchain."
as_traiter sh -c "cd '${CLEAVE_SRC}/tools/manifest-gen' && GOWORK=off go build -o manifest-gen ." \
    || log "WARNING: manifest-gen warm build failed; the timer will retry, but check the Go toolchain."

# --- Units ------------------------------------------------------------------

TMP_SERVICE=$(mktemp -t cleave-traiter.service.XXXXXX)
TMP_TIMER=$(mktemp -t cleave-traiter.timer.XXXXXX)
trap 'rm -f "$TMP_SERVICE" "$TMP_TIMER"' EXIT

cat >"$TMP_SERVICE" <<EOF
[Unit]
Description=Cleave trait build + publish (rebuild -> gen-manifest -> R2, UNSIGNED)
Documentation=https://codeberg.org/atomdrift/cleave
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${SERVICE_USER}
Group=${SERVICE_USER}

# Dedicated state tree for the trait publisher.
StateDirectory=traiter
StateDirectoryMode=0750

WorkingDirectory=${CLEAVE_SRC}
Environment=HOME=${STATE_HOME}
Environment=CARGO_HOME=${CARGO_HOME_DIR}
Environment=RUSTUP_HOME=${RUSTUP_HOME_DIR}
Environment=GOTOOLCHAIN=local
Environment=PATH=${RUN_PATH}
# cleave-traits checkout the cycle fast-forwards + publishes (TRAITS overrides the
# Makefile's ../cleave-traits default).
Environment=TRAITS=${TRAITS_DIR}
# Rendered manifest/bundle output + the change-detection stamp, kept under state.
Environment=DIST=${DIST_DIR}
Environment=TRAITS_STAMP=${STAMP_FILE}
# Versions to compat-test, including HEAD (HEAD + last VERSIONS-1 release tags).
Environment=VERSIONS=${VERSIONS}
# Refresh the cleave source + release tags before each tick so deployed code and
# the manifest's version keys track origin without a redeploy — clone-once,
# fetch-each-cycle, never a re-clone. --tags is required: publish-traits-cron gates
# on the release-tag set. Best-effort ('-'): on fetch failure, use the code on disk.
ExecStartPre=-/bin/sh -c '/usr/bin/git -C ${CLEAVE_SRC} fetch -q --tags --depth=1 origin main && /usr/bin/git -C ${CLEAVE_SRC} reset --hard -q FETCH_HEAD'
ExecStart=${MAKE_BIN} publish-traits-cron

# Yield to anything else on the host: the compat-test matrix is a heavy rebuild.
Nice=10
CPUWeight=20
IOSchedulingClass=idle
MemoryMax=50%
TasksMax=4096
# A cycle that overruns is killed; the next tick retries with a warm cargo cache.
TimeoutStartSec=25min

# Filesystem isolation. Everything the cycle writes (checkouts, caches, creds)
# lives under StateDirectory, so strict confinement still leaves it room to work.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateMounts=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
UMask=0077

NoNewPrivileges=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

StandardOutput=journal
StandardError=journal
EOF

cat >"$TMP_TIMER" <<EOF
[Unit]
Description=30-minute cleave trait build + publish
Documentation=https://codeberg.org/atomdrift/cleave

[Timer]
OnCalendar=${ON_CALENDAR}
# Spread off the :00/:30 marks so we don't collide with other periodic jobs.
RandomizedDelaySec=5min
AccuracySec=1min
# Run a cycle missed during downtime once on boot, instead of waiting.
Persistent=true

[Install]
WantedBy=timers.target
EOF

units_changed=0
for pair in "$TMP_SERVICE:$SERVICE_FILE" "$TMP_TIMER:$TIMER_FILE"; do
    src=${pair%%:*}; dst=${pair#*:}
    if $SUDO cmp -s "$src" "$dst" 2>/dev/null; then
        log "$(basename "$dst") unchanged"
    else
        log "Writing $dst"
        $SUDO install -m 0644 -o root -g root "$src" "$dst"
        units_changed=1
    fi
done

# --- Activate ---------------------------------------------------------------

[ "$units_changed" -eq 1 ] && $SUDO systemctl daemon-reload

$SUDO systemctl enable --now "${SERVICE_NAME}.timer" >/dev/null
log "Timer enabled:"
$SUDO systemctl --no-pager list-timers "${SERVICE_NAME}.timer" || true

if [ -n "$RUN_NOW" ]; then
    log "Running one cycle now (RUN_NOW=1)"
    $SUDO systemctl start "${SERVICE_NAME}.service" || true
    $SUDO systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
fi

# --- Credential readiness summary -------------------------------------------

echo
log "Credential check (the timer fires regardless; fix any MISSING before it runs):"
missing=0

if as_traiter git -C "${TRAITS_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf '    [ ok ] cleave-traits checkout: %s\n' "${TRAITS_DIR}"
else
    printf '    [MISS] cleave-traits checkout: clone %s into %s\n' "${TRAITS_REMOTE}" "${TRAITS_DIR}"
    missing=1
fi

if as_traiter sh -c 'command -v rclone >/dev/null 2>&1'; then
    if as_traiter rclone listremotes 2>/dev/null | grep -q .; then
        printf '    [ ok ] rclone remote(s) configured for %s\n' "${SERVICE_USER}"
    else
        printf '    [MISS] rclone present but no remote: configure the R2 remote in ~%s/.config/rclone\n' "${SERVICE_USER}"
        missing=1
    fi
else
    printf '    [MISS] rclone not installed for %s (needed for the R2 upload)\n' "${SERVICE_USER}"
    missing=1
fi

printf '    [note] UNSIGNED publish: clients that require a signature will not auto-update.\n'
printf '           See this script'\''s header to enable keyless cosign signing.\n'

echo
if [ "$missing" -eq 0 ]; then
    log "Install complete. Watch a cycle:  journalctl -u ${SERVICE_NAME}.service -f"
else
    log "Install complete, but fix the [MISS] items above; test with:  $SUDO systemctl start ${SERVICE_NAME}.service"
    log "then watch:  journalctl -u ${SERVICE_NAME}.service -e"
fi
