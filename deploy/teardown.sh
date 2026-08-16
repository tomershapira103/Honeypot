#!/usr/bin/env bash
# Tears down everything provision.sh created, in dependency order.
# Run this when the observation window is over.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck source=deploy/config.sh
source deploy/config.sh

echo "Before deleting, consider pulling logs off the VM (open the tunnel in one"
echo "terminal, run scp in another - see the SSH_KEY_PATH from provision.sh):"
echo "  gcloud compute start-iap-tunnel $INSTANCE_NAME 2200 --local-host-port=localhost:12200 --project=$PROJECT_ID --zone=$ZONE"
echo "  scp -i ~/.ssh/google_compute_engine -P 12200 -r $(whoami)@localhost:/opt/honeypot/data ./data"
echo

read -r -p "Continue with teardown? [y/N] " confirm
[[ "$confirm" == "y" || "$confirm" == "Y" ]] || { echo "Aborted."; exit 1; }

gcloud compute instances delete "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" --quiet

for rule in honeypot-allow-ssh-decoy honeypot-allow-rdp-decoy honeypot-allow-iap-ssh; do
  gcloud compute firewall-rules delete "$rule" --project="$PROJECT_ID" --quiet
done

gcloud compute networks subnets delete "$SUBNET_NAME" \
  --project="$PROJECT_ID" --region="$REGION" --quiet

gcloud compute networks delete "$VPC_NAME" --project="$PROJECT_ID" --quiet

echo "Teardown complete."
