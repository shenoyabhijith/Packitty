#!/bin/bash
# Get EC2 public IP from Terraform output

cd "$(dirname "$0")/../infrastructure" || exit 1

if [ ! -f "terraform.tfstate" ]; then
    echo "Error: No terraform state found. Deploy infrastructure first."
    exit 1
fi

IP=$(terraform output -raw instance_public_ip 2>/dev/null)

if [ -z "$IP" ]; then
    echo "Error: Could not get EC2 IP. Ensure infrastructure is deployed."
    exit 1
fi

echo "$IP"

