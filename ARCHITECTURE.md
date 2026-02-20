# Architecture

## Pipeline Overview

```
                    ┌─────────────────────────────────────────┐
                    │           Calling Host / Agent           │
                    │                                         │
                    │  Defines: source type, desired output,  │
                    │  which pipeline stages to include       │
                    └──────────────┬──────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│                    Content Pipeline                           │
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │Sanitizer │──▶│ Scanner  │──▶│ Honeypot │──▶│Quarantine│ │
│  │          │   │(windowed)│   │  Tools   │   │ + Alert  │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘ │
│                                                              │
│  Each stage is optional. Caller configures which stages      │
│  run based on source trust level and output requirements.    │
└──────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────────────────┐
                    │          Clean Output                    │
                    │  Sanitized content + threat metadata     │
                    └─────────────────────────────────────────┘
```

## Two Integration Levels

### Level 1: SDK / Service (generic)

Standalone library or microservice. Any agent framework can call it.

```
Agent Framework ──HTTP/gRPC──▶ Content Pipeline Service
                                      │
                                      ▼
                               Clean content + signals
```

**Interface:**

```json
{
  "input": {
    "content": "raw untrusted text",
    "source": "web_scrape",
    "url": "https://example.com/page",
    "contentType": "text/html"
  },
  "pipeline": {
    "sanitize": true,
    "scan": true,
    "scanModel": "gemini-2.0-flash",
    "windowSize": 250,
    "windowOverlap": 50
  }
}
```

**Response:**

```json
{
  "clean": true,
  "content": "sanitized text",
  "threats": [],
  "metadata": {
    "originalLength": 25000,
    "sanitizedLength": 24800,
    "windowsScanned": 124,
    "scanTimeMs": 450,
    "truncated": false
  }
}
```

### Level 2: OpenClaw Native

Tight integration with OpenClaw's tool system:

1. **Honeypot skill** — drops into any agent's workspace, exposes fake tools
2. **Browser/fetch hook** — automatically pipes web content through scanner before agent sees it
3. **Alert routing** — honeypot triggers alert the main agent via sessions_send
4. **Session kill** — compromised sessions terminated automatically

## Source Trust Levels

The caller defines trust level per source, which determines default pipeline config:

| Trust Level | Sanitize | Scan | Honeypot | Example Sources |
|-------------|----------|------|----------|-----------------|
| `untrusted` | ✅ | ✅ | ✅ | Web scrapes, UGC, social media, email |
| `semi-trusted` | ✅ | Optional | ✅ | Known APIs, partner services |
| `trusted` | Optional | ❌ | Optional | Internal tools, verified sources |

## Threat Response Actions

| Signal | Action |
|--------|--------|
| Scanner flags window (>0.7) | Log warning, include in metadata |
| Scanner flags window (>0.9) | Quarantine content, alert operator |
| Honeypot tool invoked | Kill session, alert operator, capture forensics |
| Sanitizer strips suspicious content | Log, include diff in metadata |

## Data Flow: Raw vs Clean Separation

```
Untrusted Source
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  RAW STORE (model has NO access)                     │
│                                                     │
│  /var/lib/untrusted-content/raw/<id>.json           │
│  {                                                  │
│    "id": "abc123",                                  │
│    "timestamp": "2026-02-20T05:20:00Z",             │
│    "source": "web_scrape",                          │
│    "url": "https://example.com/page",               │
│    "raw_content": "... original bytes ...",          │
│    "content_type": "text/html",                     │
│    "sha256": "..."                                  │
│  }                                                  │
│                                                     │
│  Purpose: forensics, replay, audit                  │
│  Access: host-only, not mounted into sandbox/agent  │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
            Pipeline runs
            (sanitize → scan → classify)
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  CLEAN OUTPUT (file, not direct context injection)   │
│                                                     │
│  /var/lib/untrusted-content/clean/<id>.json         │
│  {                                                  │
│    "id": "abc123",                                  │
│    "source_url": "https://example.com/page",        │
│    "content": "... sanitized text ...",             │
│    "scan_result": {                                 │
│      "clean": true,                                 │
│      "windows_scanned": 100,                        │
│      "flagged_windows": [],                         │
│      "confidence": 0.02                             │
│    },                                               │
│    "provenance": "untrusted:web_scrape",            │
│    "pipeline_version": "0.1.0",                     │
│    "sanitizer_actions": ["stripped_invisible", ...]  │
│  }                                                  │
│                                                     │
│  Purpose: agent reads this file when it needs the   │
│  content. Never piped directly into agent context.  │
└─────────────────────────────────────────────────────┘
```

### Why files, not direct output

A prompt injection that survives scanning could still work if piped directly
into an agent's context. Writing to a file creates a deliberate boundary:

1. **The consuming agent must choose to read it** — it's not injected automatically
2. **Metadata travels with the content** — provenance, scan results, confidence scores
3. **The raw input is preserved but isolated** — models never see it; only humans
   or forensic tools access the raw store
4. **Replay and audit** — if a honeypot fires, you can re-examine the raw input
   that caused it, test new scanner prompts against it, improve the pipeline

### Access control

| Store | Agent access | Human access | Purpose |
|-------|-------------|--------------|---------|
| Raw (`/raw/`) | ❌ None | ✅ Full | Forensics, replay, audit |
| Clean (`/clean/`) | 📄 Read file | ✅ Full | Agent consumption via file read |
| Honeypot log (`/incidents/`) | ❌ None | ✅ Full | Incident forensics |

The raw store MUST NOT be mounted into any agent sandbox, workspace, or
accessible via any tool the model can invoke. If using Docker sandboxing,
do not bind-mount it. If on host, ensure the path is outside the workspace
and not reachable via absolute path tools.

On KVM setups, this is naturally enforced — the raw store lives on the host,
the agent runs in the VM.

## Design Principles

1. **Defense in depth** — sanitizer, scanner, and honeypot are independent layers
2. **Fail safe** — if scanner is unavailable, content is quarantined (not passed through)
3. **Observable** — every stage logs decisions; forensics captured on trigger
4. **Economical** — windowed scanning exploits KV cache; honeypots are zero-cost until triggered
5. **Pluggable** — each stage can be replaced, configured, or skipped per source
6. **No direct injection** — clean output goes to files, never piped into agent context
7. **Raw isolation** — original untrusted content stored where no model can access it
