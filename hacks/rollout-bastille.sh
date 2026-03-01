#!/bin/sh
# rollout-bastille.sh - Deploy cleave into a Bastille jail
# Usage: ./rollout-bastille.sh <jail-name>

set -e

JAIL="$1"

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    echo "==> $*"
}

[ -z "$JAIL" ] && die "usage: $0 <jail-name>"

# Verify jail is accessible
bastille cmd "$JAIL" true || die "jail '$JAIL' not accessible"

log "Ensuring user 'cleave' exists"
bastille cmd "$JAIL" id -u cleave >/dev/null 2>&1 || \
    bastille cmd "$JAIL" pw useradd cleave -m -s /bin/sh -c "Cleave Service"

log "Installing dependencies"
bastille pkg "$JAIL" install -y rust go tmux upx rizin 7-zip

log "Copying source tree"
bastille cmd "$JAIL" rm -rf /home/cleave/cleave
bastille cp "$JAIL" . /home/cleave/cleave
bastille cmd "$JAIL" chown -R cleave:cleave /home/cleave/cleave

log "Building release binary"
bastille cmd "$JAIL" su -l cleave -c "cd ~/cleave && cargo build --release"

log "Creating rc.d service"
bastille cmd "$JAIL" tee /usr/local/etc/rc.d/cleave >/dev/null <<'EOF'
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
command_args="-c -f -P ${pidfile} -r -u cleave /bin/sh -c 'cd /home/cleave/cleave && exec ./target/release/cleave server --bind 0.0.0.0:8000'"

run_rc_command "$1"
EOF

bastille cmd "$JAIL" chmod 755 /usr/local/etc/rc.d/cleave

log "Enabling and restarting cleave service"
bastille sysrc "$JAIL" cleave_enable=YES
bastille service "$JAIL" cleave stop 2>/dev/null || true
bastille service "$JAIL" cleave start

log "Deployment complete"
