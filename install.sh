#!/bin/sh
# The Ordryx Bridge's installer:
#
#   curl -fsSL https://get.ordryx.com/bridge | sh
#
# It installs the one release named below, checks its files are that release's
# (by their own hash, whatever the server sent), and asks nothing. Everything goes in this user's home folder but the service, which
# needs sudo where the computer allows it without a password, and is otherwise
# this user's own. Moonraker's own files get two small additions, once, and it
# says which. Nothing here sends anything anywhere: the program it starts shows
# a code to enter in your Ordryx.
#
# This file is published at get.ordryx.com with its release filled in.
# All of it is inside main(), so a download cut short runs nothing.

set -eu

VERSION="@VERSION@"
TREE="@TREE@"
REPO="@REPO@"
ACCOUNT="@ACCOUNT@"
MIN_PYTHON="3.9"

say() { printf '  %s\n' "$*"; }
ok() { printf '  \342\234\223 %s\n' "$*"; }
stop() {
    printf '\n  %s\n\n' "$*" >&2
    exit 1
}

python_ok() {
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null
}

check_machine() {
    [ "$(uname -s)" = "Linux" ] || stop "The bridge runs on Linux. On another computer, use its Docker image."
    [ "$(id -u)" != "0" ] || stop "Run this as the user that runs Moonraker, not as root: it asks for root itself for the one thing that needs it."
    command -v git >/dev/null 2>&1 || stop "This needs git, which isn't installed: sudo apt install git"
    command -v python3 >/dev/null 2>&1 || stop "This needs Python $MIN_PYTHON or newer: sudo apt install python3 python3-venv"
    python_ok python3 || stop "This needs Python $MIN_PYTHON or newer, and this computer has $(python3 -V 2>&1)."
    python3 -c 'import ensurepip, venv' 2>/dev/null || stop "This needs Python's venv: sudo apt install python3-venv"
    command -v openssl >/dev/null 2>&1 || say "No openssl here: cameras will show pictures, not live video."
    command -v systemctl >/dev/null 2>&1 || stop "This computer doesn't use systemd: use the Docker image instead."
    ok "This computer: $(uname -m), $(python3 -V 2>&1)"
}

get_release() {
    # A release is a tag, and its files have one hash (git's own, of the whole
    # folder), named here and checked: whatever the server sends, only those
    # files are what runs.
    if [ -d "$CODE/.git" ]; then
        [ "$(git -C "$CODE" remote get-url origin 2>/dev/null)" = "$REPO" ] \
            || stop "$CODE is another copy of something: move it, then run this again. Nothing was changed."
        git -C "$CODE" fetch --quiet --tags --force origin
    elif [ -e "$CODE" ] && [ -n "$(ls -A "$CODE" 2>/dev/null)" ]; then
        stop "There's already a folder $CODE: move it, then run this again. Nothing was changed."
    else
        git clone --quiet "$REPO" "$CODE"
    fi
    git -C "$CODE" cat-file -e "v$VERSION^{commit}" 2>/dev/null \
        || stop "That release ($VERSION) isn't at $REPO yet. Nothing was changed. Try again in a few minutes."
    git -C "$CODE" checkout --quiet -B main "v$VERSION^{commit}"
    git -C "$CODE" reset --quiet --hard "v$VERSION^{commit}"
    git -C "$CODE" clean -fdxq
    [ "$(git -C "$CODE" rev-parse 'HEAD^{tree}')" = "$TREE" ] \
        || stop "The download wasn't this release's files. Nothing is running."
    ok "Ordryx Bridge $VERSION, files $(printf '%.12s' "$TREE") as released"
}

make_env() {
    [ -x "$ENVDIR/bin/python" ] || python3 -m venv "$ENVDIR"
    # Its packages come from PyPI and nowhere else, whatever this computer's own
    # pip settings say. Raspberry Pi OS adds piwheels.org to every install: none
    # of its files can be the release's (their hashes differ), and where it
    # can't be reached each package waits minutes on it. Kept in the
    # environment, so Moonraker's updates read it too.
    cat >"$ENVDIR/pip.conf" <<PIP
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.org/simple
PIP
    # pip refuses anything whose bytes aren't the ones the release lists
    "$ENVDIR/bin/python" -m pip install --quiet --disable-pip-version-check --require-hashes \
        -r "$CODE/requirements.lock" || stop "Its packages didn't install. Nothing is running."
    ok "Its packages, checked against the release's list"
}

write_command() {
    mkdir -p "$HOME/.local/bin"
    cat >"$HOME/.local/bin/ordryx-bridge" <<COMMAND
#!/bin/sh
cd "$CODE" || exit 1
ORDRYX_BRIDGE_ACCOUNT="$ACCOUNT" exec "$ENVDIR/bin/python" -m ordryx_bridge "\$@"
COMMAND
    chmod 755 "$HOME/.local/bin/ordryx-bridge"
}

# What a system service gives up. A user's own service can't set these: its
# manager has no privileges to give up, and it starts already confined to them.
CONFINED="PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
CapabilityBoundingSet="

unit_file() {
    # $1: the [Install] target; $2: a line naming the user (system service only);
    # $3: what it gives up (system service only)
    cat <<UNIT
[Unit]
Description=Ordryx Bridge
Documentation=https://ordryx.com/help/bridge
After=network-online.target moonraker.service
Wants=network-online.target

[Service]
Type=simple
$2
Environment=ORDRYX_BRIDGE_ACCOUNT=$ACCOUNT
WorkingDirectory=$CODE
Environment=PYTHONUNBUFFERED=1
ExecStart=$ENVDIR/bin/python -m ordryx_bridge
Restart=always
RestartSec=10
MemoryMax=256M
NoNewPrivileges=true
$3

[Install]
WantedBy=$1
UNIT
}

lingering() {
    loginctl enable-linger "$(id -un)" 2>/dev/null \
        || [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" = "yes" ]
}

start_service() {
    mkdir -p "$DATA"
    chmod 700 "$DATA"
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        unit_file multi-user.target "User=$(id -un)" "ReadWritePaths=$DATA
$CONFINED" | sudo -n tee /etc/systemd/system/ordryx-bridge.service >/dev/null
        sudo -n systemctl daemon-reload
        sudo -n systemctl enable --quiet ordryx-bridge
        sudo -n systemctl restart ordryx-bridge
        sudo -n ln -sf "$HOME/.local/bin/ordryx-bridge" /usr/local/bin/ordryx-bridge
        SERVICE="system"
        ok "Service ordryx-bridge: on, and on after a restart"
        return 0
    fi
    # No password-free sudo: this user's own service, kept running by lingering
    if lingering \
        && XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" systemctl --user show-environment >/dev/null 2>&1; then
        export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
        mkdir -p "$HOME/.config/systemd/user"
        unit_file default.target "" "" >"$HOME/.config/systemd/user/ordryx-bridge.service"
        systemctl --user daemon-reload
        systemctl --user enable --quiet ordryx-bridge
        systemctl --user restart ordryx-bridge
        SERVICE="user"
        ok "Service ordryx-bridge (this user's): on, and on after a restart"
        return 0
    fi
    stop "This user can't set up a service here. Ask whoever runs this computer to run:  sudo loginctl enable-linger $(id -un)  then run this command again."
}

moonraker_entries() {
    # A printer's Pi: updates show in Mainsail's and Fluidd's panel, beside
    # Klipper's, and Moonraker may restart the service. Each added once.
    conf="$HOME/printer_data/config/moonraker.conf"
    asvc="$HOME/printer_data/moonraker.asvc"
    [ -f "$conf" ] || return 0
    if [ "$SERVICE" != "system" ]; then
        # (Moonraker can't restart another user's own service: no entry for it)
        say "To update it later, run the same command again."
        return 0
    fi
    changed=""
    # Moonraker restarts a service for an update only when the entry has the
    # service's own name. Releases before 0.3.2 wrote ordryx_bridge, which it
    # warned about and wouldn't restart: renamed here, the rest left as it is.
    if grep -q '^\[update_manager ordryx_bridge\]' "$conf"; then
        sed 's/^\[update_manager ordryx_bridge\]/[update_manager ordryx-bridge]/' "$conf" >"$DATA/moonraker.conf.new"
        cat "$DATA/moonraker.conf.new" >"$conf" # (the file keeps its owner and mode)
        rm -f "$DATA/moonraker.conf.new"
        changed="yes"
        ok "Renamed [update_manager ordryx_bridge] to [update_manager ordryx-bridge] in $conf"
    fi
    if ! grep -q '^\[update_manager ordryx-bridge\]' "$conf"; then
        cat >>"$conf" <<ENTRY

[update_manager ordryx-bridge]
type: git_repo
path: $CODE
origin: $REPO
primary_branch: main
virtualenv: $ENVDIR
requirements: requirements.lock
managed_services: ordryx-bridge
ENTRY
        changed="yes"
        ok "Added [update_manager ordryx-bridge] to $conf"
    fi
    if [ -f "$asvc" ] && ! grep -qx 'ordryx-bridge' "$asvc"; then
        printf 'ordryx-bridge\n' >>"$asvc"
        changed="yes"
        ok "Added ordryx-bridge to $asvc"
    fi
    [ -n "$changed" ] || return 0
    restart_moonraker
}

restart_moonraker() {
    # Through its own API, and never mid-print
    command -v curl >/dev/null 2>&1 || {
        say "Moonraker will show the update entry after its next restart."
        return 0
    }
    state=$(curl -fsS --max-time 5 'http://127.0.0.1:7125/printer/objects/query?print_stats=state' 2>/dev/null || true)
    case "$state" in
        *'"printing"'* | *'"paused"'*)
            say "It's printing, so Moonraker wasn't restarted: the update entry shows after its next restart."
            ;;
        '')
            say "Moonraker didn't answer: the update entry shows after its next restart."
            ;;
        *)
            if curl -fsS --max-time 5 -X POST 'http://127.0.0.1:7125/machine/services/restart?service=moonraker' >/dev/null 2>&1; then
                ok "Moonraker restarted, through its own API, with no print running"
            else
                say "Moonraker wasn't restarted: the update entry shows after its next restart."
            fi
            ;;
    esac
}

show_code() {
    n=0
    while [ "$n" -lt 30 ]; do
        if out=$("$HOME/.local/bin/ordryx-bridge" code 2>/dev/null); then
            printf '\n  Connect it to your shop\n\n'
            printf '    In Ordryx, open  Printers > Printer setup > Add a bridge\n    and enter:\n\n'
            printf '                  %s\n\n' "$out"
            printf '    You can close this: the code renews itself, and\n'
            printf '    ordryx-bridge code  shows the current one.\n\n'
            return 0
        fi
        if "$HOME/.local/bin/ordryx-bridge" status 2>/dev/null | grep -q 'Shop  '; then
            ok "Already paired: its pairing stays as it was."
            "$HOME/.local/bin/ordryx-bridge" status
            return 0
        fi
        n=$((n + 1))
        sleep 1
    done
    if [ "$SERVICE" = "user" ]; then
        systemctl --user is-active --quiet ordryx-bridge \
            || stop "It isn't running. Its log: journalctl --user -u ordryx-bridge"
    else
        sudo -n systemctl is-active --quiet ordryx-bridge \
            || stop "It isn't running. Its log: journalctl -u ordryx-bridge"
    fi
    say "It's running, but has no code yet: it can't reach the Ordryx account just now."
    say "It keeps trying. ordryx-bridge code shows the code when it comes."
}

main() {
    case "$TREE" in
        @*) stop "This is the installer before its release is filled in. Use:  curl -fsSL https://get.ordryx.com/bridge | sh" ;;
    esac
    umask 022
    cd "$HOME" # (python -m runs what's in the folder it's started from)
    CODE="$HOME/ordryx-bridge"
    ENVDIR="$HOME/ordryx-bridge-env"
    DATA="$HOME/.ordryx-bridge"
    SERVICE=""
    printf '\n  Ordryx Bridge %s\n\n' "$VERSION"
    check_machine
    get_release
    make_env
    write_command
    start_service
    moonraker_entries
    show_code
}

main "$@"
