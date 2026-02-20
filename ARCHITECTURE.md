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
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌──────────┐ │
│  │Sanitizer │─▶│Guardrail │─▶│ Scanner  │─▶│Honeypot│─▶│Quarantine│ │
│  │          │  │Classifier│  │(windowed)│  │ Tools  │  │ + Alert  │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  └──────────┘ │
│                                                                      │
│  Each stage is optional. Caller configures which stages              │
│  run based on source trust level and output requirements.            │
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
    "guardrail": true,
    "guardrailModel": "qwenguard-7b",
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
    "guardrail": {
      "model": "qwenguard-7b",
      "categories": {
        "prompt_injection": 0.02,
        "jailbreak": 0.01,
        "harmful_content": 0.03,
        "safe": 0.97
      },
      "verdict": "pass",
      "latencyMs": 48
    },
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

## Guardrail Classifier Stage

### Purpose

Fast, local binary/multi-class classification of content against known threat
taxonomies. Runs **before** the windowed scanner to catch known-pattern attacks
cheaply, reserving the more expensive LLM scanner for novel/subtle injections.

### Model Options

| Model | Size | Taxonomy | Notes |
|-------|------|----------|-------|
| **QwenGuard** (recommended) | ~7B | Prompt injection, jailbreak, harmful content, PII | Most modern, actively maintained, broad coverage |
| LlamaGuard 3 | 8B | 13 hazard categories (MLCommons) | Well-established, Meta-backed |
| ShieldGemma | 2B/9B | Sexually explicit, dangerous, harassment, hate | Google, smaller option available |
| PromptGuard | 86M | Prompt injection + jailbreak only | Tiny, very fast, narrow scope |

**Default recommendation: QwenGuard** — best balance of coverage, modernity,
and community support. If running on constrained hardware, PromptGuard (86M)
as a fast first pass, then QwenGuard for flagged content.

### Integration

The guardrail classifier runs on the full sanitized content (post-sanitizer,
pre-scanner). It's a single inference call, not windowed — these models are
designed for exactly this classification task and handle full documents.

```
Sanitized Content
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  Guardrail Classifier                                │
│                                                     │
│  Input:  sanitized text (may be chunked for long    │
│          content, but chunks are large — 4K+ tokens)│
│  Output: category labels + confidence scores        │
│                                                     │
│  Categories (QwenGuard):                            │
│    - prompt_injection (0.0-1.0)                     │
│    - jailbreak (0.0-1.0)                            │
│    - harmful_content (0.0-1.0)                      │
│    - pii_exposure (0.0-1.0)                         │
│    - safe (0.0-1.0)                                 │
│                                                     │
│  Thresholds (configurable):                         │
│    > 0.9: block + quarantine (skip scanner)         │
│    > 0.7: flag + continue to scanner for detail     │
│    < 0.7: pass to scanner or skip (trust level)     │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
           Scanner (if needed)
```

### Why This Stage Exists

The windowed LLM scanner is powerful but expensive — it runs N small inference
calls per document. The guardrail classifier is a single call on a small
specialized model. The economics:

| Stage | Model | Calls per doc | Latency | Cost |
|-------|-------|---------------|---------|------|
| Guardrail | QwenGuard 7B (local) | 1 | ~50ms | ~free (local GPU) |
| Scanner | Gemini Flash / Kimi K2.5 | N (windows) | ~500ms-2s | API tokens |

For content that's obviously malicious (known injection patterns, jailbreak
templates), the guardrail catches it in 50ms and the scanner never runs.
The scanner is reserved for the subtle stuff — novel injections, context-dependent
attacks, adversarial content that doesn't match known patterns.

### Deployment

Assumes access to a system running the classifier model. Options:

1. **Local GPU** (preferred) — run via vLLM, Ollama, or TGI on Blackwells/consumer GPU
2. **Kamiwaza Tokenator** — deploy QwenGuard as a model, hit the OpenAI-compatible endpoint
3. **Remote API** — if a hosted guardrail service exists

```json
{
  "guardrail": {
    "enabled": true,
    "model": "qwenguard-7b",
    "endpoint": "http://localhost:8080/v1/chat/completions",
    "blockThreshold": 0.9,
    "flagThreshold": 0.7,
    "fallbackOnError": "quarantine"
  }
}
```

`fallbackOnError: "quarantine"` means if the classifier is unavailable, content
is quarantined (fail safe), not passed through.

### Relationship to Other Stages

```
Sanitizer → strips known-bad patterns (regex, unicode normalization)
Guardrail → catches known threat taxonomies (fast classifier model)
Scanner   → catches novel/subtle injections (LLM reasoning over windows)
Honeypot  → catches anything that survived all above (runtime tripwire)
```

Each layer is independent and catches a different class of threat:
- Sanitizer: structural attacks (invisible chars, encoding tricks)
- Guardrail: pattern attacks (known injection templates, jailbreak patterns)
- Scanner: semantic attacks (novel injections that require reasoning to detect)
- Honeypot: behavioral attacks (whatever survived processing, caught at execution)

## Source Trust Levels

The caller defines trust level per source, which determines default pipeline config:

| Trust Level | Sanitize | Guardrail | Scan | Honeypot | Example Sources |
|-------------|----------|-----------|------|----------|-----------------|
| `untrusted` | ✅ | ✅ | ✅ | ✅ | Web scrapes, UGC, social media, email |
| `semi-trusted` | ✅ | ✅ | Optional | ✅ | Known APIs, partner services |
| `trusted` | Optional | Optional | ❌ | Optional | Internal tools, verified sources |

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
