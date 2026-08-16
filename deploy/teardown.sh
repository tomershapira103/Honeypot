#!/usr/bin/env bash
# Tears down everything provision.sh created, in dependency order.
# Run this when the observation window is over.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck source=deploy/config.sh
source deploy/config.sh

echo "Before deleting, consider pulling logs off the VM:"
echo "  gcloud compute scp --project=$PROJECT_ID --zone=$ZONE --ssh-flag='-p 2200' --recurse \\"
echo "    $INSTANCE_NAME:/opt/honeypot/data ./data"
echo

read -r -p "Continue with teardown? [y/N] " confirm
[[ "$confirm" == "y" || "$confirm" == "Y" ]] || { echo "Aborted."; exit 1; }

gcloud compute instances delete "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" --quiet

for rule in honeypot-allow-ssh-decoy honeypot-allow-rdp-decoy honeypot-allow-admin-ssh; do
  gcloud compute firewall-rules delete "$rule" --project="$PROJECT_ID" --quiet
done

gcloud compute networks subnets delete "$SUBNET_NAME" \
  --project="$PROJECT_ID" --region="$REGION" --quiet

gcloud compute networks delete "$VPC_NAME" --project="$PROJECT_ID" --quiet

echo "Teardown complete."
