#!/usr/bin/env bash
# GCE startup-script metadata. Runs as root on every boot.
#
# This only handles the part that MUST happen unattended before the box is
# reachable: moving real sshd off port 22 and installing Docker. Copying the
# honeypot code onto the VM and starting the containers is done separately
# by provision.sh (via scp+ssh) once the VM is confirmed reachable on 2200 -
# that keeps this script self-contained (no dependency on the repo already
# being published anywhere) and its failures easy to see in the serial log.
set -euo pipefail
exec > >(tee -a /var/log/honeypot-startup.log) 2>&1

echo "=== [1/2] Moving real sshd to port 2200 ==="
# Debian 12 uses systemd socket activation for sshd (ssh.socket listens on
# 22 independently of sshd_config), so editing sshd_config alone is not
# enough - the socket unit must be disabled and the service run directly.
systemctl disable --now ssh.socket
sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
grep -q '^Port 2200' /etc/ssh/sshd_config || echo 'Port 2200' >> /etc/ssh/sshd_config
# `enable` (not just `start`) would fail here: this image's ssh.service has
# no [Install] section since it's meant to be socket-activated only, so
# `systemctl enable ssh.service` errors out. That's fine - this script
# re-runs on every boot via GCE's startup-script mechanism, so we don't
# need systemd to auto-start it; just start it now.
systemctl restart ssh.service

if ! ss -tlnp | grep -q ':2200'; then
  echo "FATAL: sshd is not listening on 2200 - aborting before exposing the box." >&2
  exit 1
fi
echo "sshd confirmed listening on 2200."

echo "=== [2/2] Installing Docker ==="
apt-get update -y
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
mkdir -p /opt/honeypot

echo "Startup script complete. Waiting for honeypot code to be deployed via provision.sh."
