#!/bin/bash
API_URL="${API_URL:-http://localhost:8080}"

curl -X PUT "$API_URL/target" \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "scanme.nmap.org",
    "profile": "default"
  }'
