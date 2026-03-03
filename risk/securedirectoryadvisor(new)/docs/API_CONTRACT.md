# Scan Result Contract

This contract describes the scan-result payload produced by analyzer functions.

## Common fields

```json
{
  "type": "file | url | email",
  "overall_risk": "safe | caution | danger",
  "risk_score": 0,
  "confidence": "low | medium | high",
  "verdict_summary": "string",
  "signal_titles": ["string"],
  "risk_report": {
    "frameworks": ["string"],
    "text": "plain text report"
  },
  "findings": [
    {
      "risk": "safe | caution | danger",
      "title": "string",
      "detail": "string"
    }
  ],
  "scanned_at": "ISO-8601 timestamp"
}
```

## File result extras

```json
{
  "type": "file",
  "filename": "string",
  "filepath": "string",
  "file_hash": "sha256 | null",
  "file_size_bytes": 0,
  "file_size": "human readable",
  "ext": ".ext"
}
```

## URL result extras

```json
{
  "type": "url",
  "url": "user input string"
}
```

## Email result extras

```json
{
  "type": "email",
  "sender": "string (From header)",
  "sender_email": "string (parsed address)",
  "sender_domain": "string",
  "subject": "string",
  "attachment_count": 0,
  "url_count": 0
}
```

## Compatibility notes

- `overall_risk` is the canonical severity for UI actions.
- `risk_score` and `confidence` are additional explainability fields.
- New fields should be additive only to preserve history compatibility.

## Email Auth Config Compatibility

- Legacy schema remains supported:
  - `email_auth_mode` = `google_oauth` | `microsoft_oauth` | `yahoo_oauth`
  - `email_oauth_provider` may be blank.
- Hybrid schema is also accepted:
  - `email_auth_mode` = `oauth`
  - `email_oauth_provider` = `google` | `microsoft` | `yahoo`
  - Runtime normalizes this to a provider-specific legacy auth mode.
- Password mode remains:
  - `email_auth_mode` = `password`
  - `email_oauth_provider` should be blank.
- Invalid/unknown OAuth provider values in generic schema safely fall back to `password` mode.
