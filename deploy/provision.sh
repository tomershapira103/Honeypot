#!/usr/bin/env bash
# Provisions the honeypot from scratch: dedicated VPC, firewall rules, VM,
# then deploys this repo onto the VM and starts the containers.
#
# Safe to re-run: every resource-creation step is skipped if it already
# exists, so if this script fails partway through you can just run it again
# to pick up where it left off.
#
# Requires: gcloud CLI authenticated (`gcloud auth login`), your account
# having the "IAP-secured Tunnel User" (roles/iap.tunnelResourceAccessor)
# role or broader (project Owner/Editor already includes it), and
# deploy/config.sh filled in (copy deploy/config.sh.example -> config.sh).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck source=deploy/config.sh
source deploy/config.sh

echo "=== Enabling required APIs ==="
gcloud services enable compute.googleapis.com iap.googleapis.com --project="$PROJECT_ID"

echo "=== Creating isolated VPC + subnet ==="
# A custom VPC has NO implicit allow rules (unlike the auto-created
# "default" network), so this is isolated by default until we add the
# firewall rules below.
if gcloud compute networks describe "$VPC_NAME" --project="$PROJECT_ID" &>/dev/null; then
  echo "  $VPC_NAME already exists, skipping"
else
  gcloud compute networks create "$VPC_NAME" \
    --project="$PROJECT_ID" --subnet-mode=custom
fi

if gcloud compute networks subnets describe "$SUBNET_NAME" --project="$PROJECT_ID" --region="$REGION" &>/dev/null; then
  echo "  $SUBNET_NAME already exists, skipping"
else
  gcloud compute networks subnets create "$SUBNET_NAME" \
    --project="$PROJECT_ID" --network="$VPC_NAME" \
    --region="$REGION" --range="$SUBNET_RANGE"
fi

echo "=== Creating firewall rules ==="
create_firewall_rule_if_missing() {
  local name="$1" port="$2" source_range="$3"
  if gcloud compute firewall-rules describe "$name" --project="$PROJECT_ID" &>/dev/null; then
    echo "  $name already exists, skipping"
    return
  fi
  gcloud compute firewall-rules create "$name" \
    --project="$PROJECT_ID" --network="$VPC_NAME" \
    --direction=INGRESS --action=ALLOW --rules="tcp:$port" \
    --source-ranges="$source_range" --target-tags=honeypot
}

create_firewall_rule_if_missing honeypot-allow-ssh-decoy 22 0.0.0.0/0
create_firewall_rule_if_missing honeypot-allow-rdp-decoy 3389 0.0.0.0/0
# Admin SSH (port 2200) is reachable ONLY through GCP's Identity-Aware Proxy
# (IAP), never directly from the internet. IAP authenticates by your Google
# identity (IAM), not by source IP, so this keeps working even if your
# home/office IP changes - unlike a plain IP-allowlisted firewall rule.
create_firewall_rule_if_missing honeypot-allow-iap-ssh 2200 35.235.240.0/20

echo "=== Creating VM (no service account / no scopes: isolated even if compromised) ==="
if gcloud compute instances describe "$INSTANCE_NAME" --project="$PROJECT_ID" --zone="$ZONE" &>/dev/null; then
  echo "  $INSTANCE_NAME already exists, skipping"
else
  gcloud compute instances create "$INSTANCE_NAME" \
    --project="$PROJECT_ID" --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family=debian-12 --image-project=debian-cloud \
    --network="$VPC_NAME" --subnet="$SUBNET_NAME" \
    --tags=honeypot \
    --no-service-account --no-scopes \
    --metadata-from-file=startup-script=deploy/startup.sh
fi

EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
echo "VM external IP: $EXTERNAL_IP"

echo "=== Provisioning admin SSH key ==="
SSH_KEY_PATH="$HOME/.ssh/google_compute_engine"
SSH_USER="$(whoami)"
if [[ ! -f "$SSH_KEY_PATH" ]]; then
  ssh-keygen -t rsa -b 2048 -f "$SSH_KEY_PATH" -C "$SSH_USER" -N ""
fi
gcloud compute instances add-metadata "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  --metadata="ssh-keys=${SSH_USER}:$(cat "${SSH_KEY_PATH}.pub")"

echo "=== Opening IAP tunnel to admin sshd (port 2200) ==="
# `gcloud compute ssh --tunnel-through-iap` picks its own SSH backend, which
# on Windows defaults to PuTTY's plink.exe - its port flag is "-P", not the
# "-p" we need, so passing --ssh-flag="-p 2200" breaks there. Sidestepping
# that entirely: open a raw IAP TCP tunnel ourselves and talk to it with a
# real OpenSSH client (Git Bash ships one), which behaves identically on
# Windows/Mac/Linux.
LOCAL_PORT=12200
gcloud compute start-iap-tunnel "$INSTANCE_NAME" 2200 \
  --local-host-port="localhost:$LOCAL_PORT" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  > /tmp/honeypot-iap-tunnel.log 2>&1 &
TUNNEL_PID=$!
trap 'kill "$TUNNEL_PID" 2>/dev/null || true' EXIT

SSH_CMD=(ssh -i "$SSH_KEY_PATH" -p "$LOCAL_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SSH_USER@localhost")

echo "=== Waiting for tunnel + admin sshd (startup-script must finish first) ==="
for _ in $(seq 1 30); do
  if "${SSH_CMD[@]}" true 2>/dev/null; then
    echo "sshd on 2200 is reachable via the IAP tunnel."
    break
  fi
  echo "Not ready yet, retrying in 15s... (tunnel log: /tmp/honeypot-iap-tunnel.log)"
  sleep 15
done

echo "=== Copying honeypot code to the VM ==="
"${SSH_CMD[@]}" "sudo mkdir -p /opt/honeypot && sudo chown \$(whoami) /opt/honeypot"
scp -i "$SSH_KEY_PATH" -P "$LOCAL_PORT" -o StrictHostKeyChecking=accept-new -r \
  docker-compose.yml config analysis "$SSH_USER@localhost:/opt/honeypot/"

# Bind-mounting an empty host dir over Cowrie's /cowrie/cowrie-git/var hides
# the subdirectories the image normally seeds there (for SSH host keys, tty
# logs, downloads, JSON log) - Cowrie doesn't create missing parents itself
# and crashes on startup without them, so we have to pre-create the
# structure it expects on the host side before the first `docker compose up`.
"${SSH_CMD[@]}" "mkdir -p /opt/honeypot/data/cowrie/var/log/cowrie \
  /opt/honeypot/data/cowrie/var/lib/cowrie/tty \
  /opt/honeypot/data/cowrie/var/lib/cowrie/downloads \
  /opt/honeypot/data/trapster"

echo "=== Starting the honeypot containers ==="
"${SSH_CMD[@]}" "cd /opt/honeypot && sudo docker compose up -d --build && \
  date -u +%Y-%m-%dT%H:%M:%SZ | sudo tee analysis/deployment_marker.txt"

echo
echo "Done. Honeypot is live at $EXTERNAL_IP (ports 22, 3389)."
echo "Admin access (open the tunnel in one terminal, then ssh in another):"
echo "  gcloud compute start-iap-tunnel $INSTANCE_NAME 2200 --local-host-port=localhost:$LOCAL_PORT --project=$PROJECT_ID --zone=$ZONE"
echo "  ssh -i \"$SSH_KEY_PATH\" -p $LOCAL_PORT $SSH_USER@localhost"
