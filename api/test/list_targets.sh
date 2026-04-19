#!/bin/bash
API_URL="${API_URL:-http://localhost:8080}"

curl "$API_URL/target" \
  -H 'Content-Type: application/json'
