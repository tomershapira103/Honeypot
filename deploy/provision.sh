#!/usr/bin/env bash
# Provisions the honeypot from scratch: dedicated VPC, firewall rules, VM,
# then deploys this repo onto the VM and starts the containers.
#
# Requires: gcloud CLI authenticated (`gcloud auth login`), and
# deploy/config.sh filled in (copy deploy/config.sh.example -> config.sh).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck source=deploy/config.sh
source deploy/config.sh

echo "=== Enabling Compute Engine API ==="
gcloud services enable compute.googleapis.com --project="$PROJECT_ID"

echo "=== Creating isolated VPC + subnet ==="
# A custom VPC has NO implicit allow rules (unlike the auto-created
# "default" network), so this is isolated by default until we add the
# firewall rules below.
gcloud compute networks create "$VPC_NAME" \
  --project="$PROJECT_ID" --subnet-mode=custom

gcloud compute networks subnets create "$SUBNET_NAME" \
  --project="$PROJECT_ID" --network="$VPC_NAME" \
  --region="$REGION" --range="$SUBNET_RANGE"

echo "=== Creating firewall rules ==="
gcloud compute firewall-rules create honeypot-allow-ssh-decoy \
  --project="$PROJECT_ID" --network="$VPC_NAME" \
  --direction=INGRESS --action=ALLOW --rules=tcp:22 \
  --source-ranges=0.0.0.0/0 --target-tags=honeypot

gcloud compute firewall-rules create honeypot-allow-rdp-decoy \
  --project="$PROJECT_ID" --network="$VPC_NAME" \
  --direction=INGRESS --action=ALLOW --rules=tcp:3389 \
  --source-ranges=0.0.0.0/0 --target-tags=honeypot

gcloud compute firewall-rules create honeypot-allow-admin-ssh \
  --project="$PROJECT_ID" --network="$VPC_NAME" \
  --direction=INGRESS --action=ALLOW --rules=tcp:2200 \
  --source-ranges="${OPERATOR_IP}/32" --target-tags=honeypot

echo "=== Creating VM (no service account / no scopes: isolated even if compromised) ==="
gcloud compute instances create "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  --machine-type="$MACHINE_TYPE" \
  --image-family=debian-12 --image-project=debian-cloud \
  --network="$VPC_NAME" --subnet="$SUBNET_NAME" \
  --tags=honeypot \
  --no-service-account --no-scopes \
  --metadata-from-file=startup-script=deploy/startup.sh

EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
echo "VM external IP: $EXTERNAL_IP"

# Use `gcloud compute ssh/scp` (not plain ssh/scp) so gcloud handles first-time
# SSH key provisioning to the VM automatically; --ssh-flag targets port 2200
# since Cowrie will own port 22.
GCLOUD_SSH=(gcloud compute ssh "$INSTANCE_NAME" --project="$PROJECT_ID" --zone="$ZONE" --ssh-flag="-p 2200")

echo "=== Waiting for admin sshd on port 2200 (startup-script must finish first) ==="
for _ in $(seq 1 30); do
  if "${GCLOUD_SSH[@]}" --command="true" 2>/dev/null; then
    echo "sshd on 2200 is reachable."
    break
  fi
  echo "Not ready yet, retrying in 15s..."
  sleep 15
done

echo "=== Copying honeypot code to the VM ==="
"${GCLOUD_SSH[@]}" --command="sudo mkdir -p /opt/honeypot && sudo chown \$(whoami) /opt/honeypot"
gcloud compute scp --project="$PROJECT_ID" --zone="$ZONE" --ssh-flag="-p 2200" --recurse \
  docker-compose.yml config analysis "$INSTANCE_NAME:/opt/honeypot/"

echo "=== Starting the honeypot containers ==="
"${GCLOUD_SSH[@]}" --command="cd /opt/honeypot && sudo docker compose up -d --build && \
  date -u +%Y-%m-%dT%H:%M:%SZ | sudo tee analysis/deployment_marker.txt"

echo
echo "Done. Honeypot is live at $EXTERNAL_IP (ports 22, 3389)."
echo "Admin access: ssh -p 2200 <you>@$EXTERNAL_IP"
