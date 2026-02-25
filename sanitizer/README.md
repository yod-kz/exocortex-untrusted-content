# Content Sanitizer

Pre-processing stage that normalizes untrusted content before scanning or agent ingestion.

## Stages

### 1. Encoding normalization
- Convert to UTF-8
- Strip BOM markers
- Normalize Unicode (NFC form) — collapses confusable characters

### 2. Unprintable / invisible character removal
- Strip zero-width characters (ZWJ, ZWNJ, zero-width space)
- Remove control characters (except newline, tab)
- Strip directional override characters (used to visually hide text)
- Remove soft hyphens and other invisible formatting

### 3. Binary detection and removal
- Detect embedded binary sequences
- Strip base64 blobs above configurable size threshold
- Remove data: URIs (potential payload carriers)

### 4. Length enforcement
- Truncate to configurable max length
- Preserve structure (prefer truncating at paragraph/sentence boundaries)
- Log when truncation occurs

### 5. Structure normalization
- Collapse excessive whitespace
- Normalize line endings
- Strip HTML comments (common injection hiding spot)
- Optionally strip all HTML/markdown formatting

## Configuration

```json
{
  "maxLength": 50000,
  "stripInvisible": true,
  "stripBinary": true,
  "stripHtmlComments": true,
  "normalizeUnicode": true,
  "collapseWhitespace": true,
  "maxBase64BlobSize": 256,
  "preserveMarkdown": true
}
```

## Status

- [x] Implementation
- [x] Test suite (core sanitizer behaviors)
- [x] Integration with scanner pipeline
