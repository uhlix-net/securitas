"""The Linux agent: the RPM built into the image (Dockerfile stage "agent") and the install script Securitas serves.

GET /agent/install.sh (no sign-in: it holds only Securitas's address, the scan account name, the SSH *public* key
and the allowed source addresses) downloads the RPM from Securitas, installs it with dnf and runs
securitas-agent-setup, which creates the scan account, authorizes the key and adds the one sudo rule.
"""
import glob
import os
import shlex

AGENT_DIR = os.environ.get("SECURITAS_AGENT_DIR") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent")


def rpm_path():
    files = sorted(glob.glob(os.path.join(AGENT_DIR, "securitas-agent-*.x86_64.rpm")))
    return files[-1] if files else None


def public_key(cfg):
    """Securitas's SSH public key (from the scan credentials), or '' when none is set or readable."""
    from . import scan_linux
    if not (cfg.ssh_key or cfg.ssh_key_file):
        return ""
    try:
        k = scan_linux.load_key(cfg)
    except Exception:
        return ""
    return "%s %s securitas-scans" % (k.get_name(), k.get_base64())


SCRIPT = r"""#!/bin/bash
# Securitas agent installer for Rocky Linux / RHEL / AlmaLinux 8 and 9 (x86_64), served by %(base)s
# Run as root:  curl -fsS %(base)s/agent/install.sh | sudo bash
# (add --cacert <your CA file> to curl, and set SECURITAS_CA=<that file> for this script, if Securitas uses a
# private CA the host does not trust yet). Review it first if you like: it only installs the securitas-agent RPM
# and runs securitas-agent-setup with the values below.
set -euo pipefail
BASE=%(q_base)s
SCAN_USER=%(q_user)s
SCAN_KEY=%(q_key)s
SCAN_FROM=%(q_from)s
[ "$(id -u)" = 0 ] || { echo "Run this as root (sudo bash)." >&2; exit 1; }
[ -n "$SCAN_KEY" ] || { echo "Securitas has no SSH key yet: an admin must set Settings > Scan credentials first." >&2; exit 1; }
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in *rhel*|*fedora*|*rocky*|*almalinux*|*centos*) ;; *) echo "Only RHEL-family hosts are supported (this is ${PRETTY_NAME:-unknown})." >&2; exit 1 ;; esac
[ "$(uname -m)" = x86_64 ] || { echo "Only x86_64 hosts are supported." >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
echo "Downloading the Securitas agent from $BASE ..."
curl -fsS ${SECURITAS_CA:+--cacert "$SECURITAS_CA"} -o "$tmp/securitas-agent.x86_64.rpm" "$BASE/agent/securitas-agent.rpm"
dnf -y -q install "$tmp/securitas-agent.x86_64.rpm"
rpm -q securitas-agent
securitas-agent-setup --user "$SCAN_USER" --key "$SCAN_KEY" ${SCAN_FROM:+--from "$SCAN_FROM"}
"""


def install_script(base, user, key, allowed_from):
    q = shlex.quote
    return SCRIPT % {"base": base, "q_base": q(base), "q_user": q(user or "svc-securitas"), "q_key": q(key or ""),
                     "q_from": q(allowed_from or "")}
