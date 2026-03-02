#!/bin/sh
# rollout-bastille.sh - Deploy cleave using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>

set -e

BUILD="$1"
RUN="$2"

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    echo "==> $*"
}

[ -z "$BUILD" ] || [ -z "$RUN" ] && die "usage: $0 <build-jail> <run-jail>"

# Verify jails are accessible
doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

# --- Build jail setup ---

log "Ensuring build user exists"
doas bastille cmd "$BUILD" id -u cleave >/dev/null 2>&1 || \
    doas bastille cmd "$BUILD" pw useradd cleave -m -s /bin/sh -c "Cleave Build"

log "Installing build dependencies"
doas bastille pkg "$BUILD" install -y rust go sccache

log "Copying source tree to build jail"
doas bastille cmd "$BUILD" rm -rf /home/cleave/cleave
doas bastille cp "$BUILD" . /home/cleave/cleave
doas bastille cmd "$BUILD" chown -R cleave:cleave /home/cleave/cleave

log "Building tarball"
doas bastille cmd "$BUILD" su -l cleave -c "cd ~/cleave && RUSTC_WRAPPER=sccache make tarball"

# --- Transfer tarball via jail filesystem ---

log "Transferring tarball to run jail"
BASTILLE_DIR="/usr/local/bastille/jails"
doas cp "$BASTILLE_DIR/$BUILD/root/home/cleave/cleave/out/cleave.tgz" \
       "$BASTILLE_DIR/$RUN/root/tmp/cleave.tgz"

# --- Run jail setup ---

log "Ensuring run user exists"
doas bastille cmd "$RUN" id -u cleave >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd cleave -m -s /bin/sh -c "Cleave Service"

log "Extracting tarball"
doas bastille cmd "$RUN" rm -rf /usr/local/share/cleave
doas bastille cmd "$RUN" mkdir -p /usr/local/share/cleave
doas bastille cmd "$RUN" tar -xzf /tmp/cleave.tgz -C /usr/local/share/cleave
doas bastille cmd "$RUN" rm -f /tmp/cleave.tgz

log "Creating rc.d service"
doas bastille cmd "$RUN" tee /usr/local/etc/rc.d/cleave >/dev/null <<'EOF'
#!/bin/sh

# PROVIDE: cleave
# REQUIRE: LOGIN DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="cleave"
rcvar="cleave_enable"

load_rc_config $name

: ${cleave_enable:="NO"}

pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
cleave_env="CLEAVE_TRAITS_DIR=/usr/local/share/cleave/traits"
command_args="-c -f -P ${pidfile} -r -u cleave /usr/bin/env ${cleave_env} /usr/local/share/cleave/cleave server --bind 0.0.0.0:8000"

run_rc_command "$1"
EOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/cleave

log "Enabling and restarting cleave service"
doas bastille sysrc "$RUN" cleave_enable=YES
doas bastille service "$RUN" cleave stop 2>/dev/null || true
doas bastille service "$RUN" cleave start

log "Deployment complete"
