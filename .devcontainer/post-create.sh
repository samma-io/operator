#!/bin/bash
set -e

echo "Installing operator dependencies..."
pip install -r operator/requirements.txt

echo "Installing API dependencies..."
pip install -r api/code/requirements.txt

echo "Creating k3d cluster if not exists..."
if ! k3d cluster list | grep -q samma-dev; then
  k3d cluster create samma-dev --wait
fi

echo "Applying CRD and namespace..."
kubectl apply -f manifest/samma-operator.yaml

echo "Dev environment ready!"
