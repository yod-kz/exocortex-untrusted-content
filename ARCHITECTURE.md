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

## Design Principles

1. **Defense in depth** — sanitizer, scanner, and honeypot are independent layers
2. **Fail safe** — if scanner is unavailable, content is quarantined (not passed through)
3. **Observable** — every stage logs decisions; forensics captured on trigger
4. **Economical** — windowed scanning exploits KV cache; honeypots are zero-cost until triggered
5. **Pluggable** — each stage can be replaced, configured, or skipped per source
