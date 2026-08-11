#!/usr/bin/env bash

set -euo pipefail

port="${PORT:-8080}"
agent_url="http://127.0.0.1:${port}"

if ! command -v cloudflared >/dev/null 2>&1; then
  printf '%s\n' "cloudflared is required for the local GitHub webhook tunnel."
  printf '%s\n' "Install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
  exit 1
fi

if ! curl --fail --silent --show-error "${agent_url}/health" >/dev/null; then
  printf '%s\n' "NightZero Agent is not responding at ${agent_url}/health. Start it before opening the tunnel."
  exit 1
fi

printf '%s\n' "Opening a temporary public tunnel to ${agent_url}."
printf '%s\n' "Copy the https URL printed by cloudflared and append /api/v1/webhooks/github in the GitHub webhook configuration."
printf '%s\n' "Press Ctrl+C to close the tunnel."

exec cloudflared tunnel --url "${agent_url}"