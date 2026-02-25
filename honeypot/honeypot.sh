#!/usr/bin/env bash
# honeypot.sh — Prompt injection tripwire
#
# Called by OpenClaw when a honeypot tool is invoked.
# Instead of executing, this logs the attempt, captures forensics,
# alerts the main agent, and kills the compromised session.
#
# Usage: honeypot.sh <tool_name> <session_key> [<arguments_json>]
#
# Environment:
#   HONEYPOT_CONFIG    Path to config.json (default: ./config.json)
#   GATEWAY_TOKEN      Gateway auth token (overrides config)
#   GATEWAY_HOST       Gateway host (overrides config, default: 127.0.0.1)
#   GATEWAY_PORT       Gateway port (overrides config, default: 18789)
#   PIPELINE_API_URL   Optional untrusted-content API base URL

set -euo pipefail

TOOL_NAME="${1:-unknown}"
SESSION_KEY="${2:-unknown}"
RAW_ARGS_JSON="${3:-{}}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ARGS_JSON_PARSED="$(printf '%s' "$RAW_ARGS_JSON" | jq -c . 2>/dev/null)"; then
    ARGS_JSON="$ARGS_JSON_PARSED"
else
    ARGS_JSON="{}"
fi

# --- Load config ---
CONFIG_PATH="${HONEYPOT_CONFIG:-$(dirname "$0")/config.json}"
if [[ -f "$CONFIG_PATH" ]]; then
    GATEWAY_HOST="${GATEWAY_HOST:-$(jq -r '.gatewayHost // "127.0.0.1"' "$CONFIG_PATH")}"
    GATEWAY_PORT="${GATEWAY_PORT:-$(jq -r '.gatewayPort // 18789' "$CONFIG_PATH")}"
    GATEWAY_TOKEN="${GATEWAY_TOKEN:-$(jq -r '.gatewayToken // ""' "$CONFIG_PATH")}"
    ALERT_SESSION="${ALERT_SESSION:-$(jq -r '.alertSessionKey // "agent:main:main"' "$CONFIG_PATH")}"
    PIPELINE_API_URL="${PIPELINE_API_URL:-$(jq -r '.pipelineApiUrl // ""' "$CONFIG_PATH")}"
    LOG_PATH="$(jq -r '.logPath // "/var/log/honeypot"' "$CONFIG_PATH")"
    KILL_ON_TRIGGER="$(jq -r 'if has("killOnTrigger") then .killOnTrigger else true end' "$CONFIG_PATH")"
    SNAPSHOT_BROWSER="$(jq -r 'if has("snapshotBrowser") then .snapshotBrowser else true end' "$CONFIG_PATH")"
else
    GATEWAY_HOST="${GATEWAY_HOST:-127.0.0.1}"
    GATEWAY_PORT="${GATEWAY_PORT:-18789}"
    GATEWAY_TOKEN="${GATEWAY_TOKEN:-}"
    ALERT_SESSION="${ALERT_SESSION:-agent:main:main}"
    PIPELINE_API_URL="${PIPELINE_API_URL:-}"
    LOG_PATH="/var/log/honeypot"
    KILL_ON_TRIGGER="true"
    SNAPSHOT_BROWSER="true"
fi

GATEWAY_URL="http://${GATEWAY_HOST}:${GATEWAY_PORT}"

# --- Ensure log directory ---
mkdir -p "$LOG_PATH"

# --- Log the attempt ---
INCIDENT_ID="$(date +%s)-$$"
INCIDENT_FILE="${LOG_PATH}/incident-${INCIDENT_ID}.json"

cat > "$INCIDENT_FILE" <<EOF
{
  "id": "${INCIDENT_ID}",
  "timestamp": "${TIMESTAMP}",
  "tool_name": "${TOOL_NAME}",
  "session_key": "${SESSION_KEY}",
  "arguments": ${ARGS_JSON},
  "hostname": "$(hostname)",
  "action_taken": "pending"
}
EOF

echo "[HONEYPOT] ${TIMESTAMP} Tool=${TOOL_NAME} Session=${SESSION_KEY}" >&2
echo "[HONEYPOT] Arguments: ${ARGS_JSON}" >&2

# --- Optional: send incident to untrusted-content pipeline ---
SAFE_ARGS="${ARGS_JSON}"
if [[ -n "$PIPELINE_API_URL" ]]; then
    curl -sf --max-time 5 \
        -X POST "${PIPELINE_API_URL%/}/v1/honeypot/trigger" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
            --arg tool "$TOOL_NAME" \
            --arg session "$SESSION_KEY" \
            --arg incident "$INCIDENT_ID" \
            --argjson arguments "$SAFE_ARGS" \
            '{tool_name: $tool, session_key: $session, incident_id: $incident, arguments: $arguments}')" \
        >/dev/null 2>&1 || echo "[HONEYPOT] Warning: failed to notify pipeline API" >&2
fi

# --- Capture browser snapshot (forensics) ---
if [[ "$SNAPSHOT_BROWSER" == "true" ]]; then
    SCREENSHOT_PATH="${LOG_PATH}/screenshot-${INCIDENT_ID}.png"
    # Attempt to capture current browser state via gateway API
    curl -sf --max-time 5 \
        -H "Authorization: Bearer ${GATEWAY_TOKEN}" \
        "${GATEWAY_URL}/api/browser/screenshot" \
        -o "$SCREENSHOT_PATH" 2>/dev/null || true
    
    if [[ -f "$SCREENSHOT_PATH" ]]; then
        echo "[HONEYPOT] Browser screenshot saved: ${SCREENSHOT_PATH}" >&2
    fi
fi

# --- Alert the main agent ---
ALERT_MSG="🚨 **HONEYPOT TRIGGERED**\n\n"
ALERT_MSG+="A prompt injection was detected on the browsing agent.\n\n"
ALERT_MSG+="**Tool called:** \`${TOOL_NAME}\`\n"
ALERT_MSG+="**Session:** \`${SESSION_KEY}\`\n"
ALERT_MSG+="**Time:** ${TIMESTAMP}\n"
ALERT_MSG+="**Arguments:** \`\`\`${ARGS_JSON}\`\`\`\n\n"
ALERT_MSG+="**Incident ID:** ${INCIDENT_ID}\n"
ALERT_MSG+="**Action:** Session killed, content quarantined.\n"
ALERT_MSG+="**Forensics:** ${INCIDENT_FILE}"

if [[ -n "$GATEWAY_TOKEN" ]]; then
    # Send alert to the main agent session
    curl -sf --max-time 10 \
        -X POST "${GATEWAY_URL}/api/sessions/send" \
        -H "Authorization: Bearer ${GATEWAY_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
            --arg key "$ALERT_SESSION" \
            --arg msg "$ALERT_MSG" \
            '{sessionKey: $key, message: $msg}')" \
        2>/dev/null || echo "[HONEYPOT] Warning: failed to send alert to gateway" >&2
fi

# --- Kill the compromised session ---
if [[ "$KILL_ON_TRIGGER" == "true" ]]; then
    echo "[HONEYPOT] Killing session: ${SESSION_KEY}" >&2
    
    if [[ -n "$GATEWAY_TOKEN" ]]; then
        # Request session termination via gateway API
        curl -sf --max-time 5 \
            -X POST "${GATEWAY_URL}/api/sessions/kill" \
            -H "Authorization: Bearer ${GATEWAY_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$(jq -n --arg key "$SESSION_KEY" '{sessionKey: $key}')" \
            2>/dev/null || echo "[HONEYPOT] Warning: failed to kill session via gateway" >&2
    fi
    
    # Update incident record
    jq '.action_taken = "session_killed"' "$INCIDENT_FILE" > "${INCIDENT_FILE}.tmp" \
        && mv "${INCIDENT_FILE}.tmp" "$INCIDENT_FILE"
fi

# --- Return fake error to the model (in case session isn't killed instantly) ---
echo '{"error": "Permission denied. This operation requires elevated privileges. Contact system administrator."}'

exit 0
