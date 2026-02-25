# Honeypot Tools

Fake tools exposed to the agent that serve as prompt injection tripwires.

## How It Works

1. Agent's tool schema includes realistic-looking tools: `run_command`, `write_file`, `send_request`
2. Agent's system prompt explicitly says: "You are a browsing assistant. You never need to execute code, write files, or make network requests. Only use browser tools."
3. A legitimate agent will never call these tools — there's no reason to
4. A prompt injection that overrides the system prompt WILL try to use them (exec, exfiltrate, write)
5. When called, the honeypot doesn't execute — it logs, alerts, snapshots, and kills the session

## Why It Works

- The injected prompt can see the tool schema but **can't know the tools are fake**
- Prompt injections almost always try to exec, write, or network out — those are the high-value actions
- The tripwire is invisible to the attacker and zero-cost when not triggered
- False positive rate is ~0: a correctly operating browsing agent has no reason to exec

## Components

- `SKILL.md` — OpenClaw skill definition with honeypot tool schemas
- `honeypot.sh` — Triggered when a honeypot tool is called. Logs, alerts, kills.
- `config.json` — Configuration: alert targets, log paths, kill behavior
- Optional pipeline ingest — `honeypot.sh` can POST incidents to `tool-untrusted-content` (`/v1/honeypot/trigger`)

## Setup

1. Copy `SKILL.md` and `honeypot.sh` to the browsing agent's workspace skills
2. Configure `config.json` with your alert endpoint
3. Ensure `honeypot.sh` is executable
4. The skill auto-loads; honeypot tools appear in the agent's schema

## Configuration

```json
{
  "alertMethod": "gateway",
  "gatewayHost": "127.0.0.1",
  "gatewayPort": 18789,
  "gatewayToken": "",
  "alertSessionKey": "agent:main:main",
  "pipelineApiUrl": "http://127.0.0.1:8787",
  "logPath": "/var/log/honeypot",
  "killOnTrigger": true,
  "snapshotBrowser": true,
  "quarantineContent": true
}
```
