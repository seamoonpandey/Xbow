# Understanding Implemented Scan Parameters

This guide documents scan option names and limits from `core/src/scan/dto/create-scan.dto.ts`. Public Core scan requests use camelCase option names.

---

## Implemented `POST /scan` options

```json
{
  "url": "https://target.example",
  "options": {
    "depth": 3,
    "maxParams": 100,
    "verifyExecution": true,
    "wafBypass": true,
    "maxPayloadsPerParam": 50,
    "timeout": 60000,
    "reportFormat": ["html", "json"],
    "singlePage": false,
    "auth": {
      "enabled": false,
      "loginUrl": "https://target.example/login",
      "username": "user",
      "password": "password",
      "usernameSelector": "input[name=\"username\"]",
      "passwordSelector": "input[name=\"password\"]",
      "submitSelector": "button[type=\"submit\"]",
      "postLoginWaitMs": 3000,
      "successUrlContains": "/dashboard"
    }
  }
}
```

Do not use stale snake_case names such as `max_params`, `verify_execution`, `waf_bypass`, `max_payloads_per_param`, or `report_format` in Core API examples. Snake_case appears only in Python microservice schemas and bridge payloads.

---

## Main tuning parameters

| Parameter | Default | DTO range | Purpose |
|---|---:|---:|---|
| `depth` | 3 | 1-10 | Crawl depth. |
| `maxParams` | 100 | 1-500 | Maximum number of unique parameters to collect during crawling. |
| `verifyExecution` | true | boolean | Whether the fuzzer should attempt browser execution verification. |
| `wafBypass` | true | boolean | Scan option flag for WAF-bypass-oriented generation behavior. |
| `maxPayloadsPerParam` | 50 | 1-200 | Maximum payload budget per parameter in the Core pipeline. |
| `timeout` | 60000 | 5000-300000 ms | Scan/fuzzer timeout budget passed through the pipeline. |
| `reportFormat` | `["html", "json"]` | `html`, `json`, `pdf` | Requested report formats. |
| `singlePage` | false | boolean | Skip crawling and scan only the submitted URL. |
| `auth` | disabled | object | Target-site login options for authenticated scanning. |

---

## `maxParams` — parameter discovery limit

`maxParams` controls how many unique parameter names the crawler should discover and collect.

Example:

```json
{
  "url": "https://example.com",
  "options": {
    "maxParams": 20
  }
}
```

A lower value makes crawling faster but can miss vulnerable parameters. A higher value increases coverage but can significantly increase scan time.

---

## `maxPayloadsPerParam` — fuzzing depth per parameter

`maxPayloadsPerParam` controls the maximum number of generated/tested payloads retained per target parameter in the Core scan pipeline.

Example:

```json
{
  "url": "https://example.com",
  "options": {
    "maxPayloadsPerParam": 50
  }
}
```

The Core payload bridge converts this camelCase value into the payload-gen microservice field `max_payloads` when calling `POST /generate`.

---

## How `maxParams` and `maxPayloadsPerParam` work together

```text
CRAWL
  └─ discover up to maxParams unique parameters
        ↓
CONTEXT
  └─ analyze reflection and allowed characters for each parameter
        ↓
PAYLOAD-GEN
  └─ request a payload budget derived from maxPayloadsPerParam
        ↓
FUZZ
  └─ test generated payloads and deduplicate results
```

Typical trade-offs:

| Scenario | Example settings | Risk |
|---|---|---|
| Narrow/deep | `maxParams=10`, `maxPayloadsPerParam=100` | Can miss parameters not reached by crawl. |
| Broad/shallow | `maxParams=200`, `maxPayloadsPerParam=5` | Can miss payload variants needed for execution. |
| Balanced | `maxParams=100`, `maxPayloadsPerParam=50` | Default balance of breadth and depth. |
| Comprehensive | `maxParams=500`, `maxPayloadsPerParam=200` | Very slow; best kept for labs or small controlled targets. |

---

## Suggested presets

These are operational suggestions, not hard-coded modes.

| Preset | Options | Use case |
|---|---|---|
| Quick | `maxParams=20`, `maxPayloadsPerParam=10` | Local smoke checks. |
| Standard | `maxParams=100`, `maxPayloadsPerParam=50` | Default balanced scanning. |
| Deep | `maxParams=200`, `maxPayloadsPerParam=100` | More thorough controlled scans. |
| Full/lab | `maxParams=500`, `maxPayloadsPerParam=200` | Research/lab targets where long runtimes are acceptable. |

---

## Target-site authentication options

`options.auth` configures login to the target application being scanned. It is separate from authentication used to call the RedSentinel API.

| Field | Required when enabled? | Purpose |
|---|---|---|
| `enabled` | no | Enables target-site login flow. |
| `loginUrl` | yes | Login page URL. |
| `username` | yes | Username to submit. |
| `password` | yes | Password to submit. |
| `usernameSelector` | no | CSS selector for username input. |
| `passwordSelector` | no | CSS selector for password input. |
| `submitSelector` | no | CSS selector for submit button. |
| `postLoginWaitMs` | no | Wait after submit; default 3000 ms, range 500-30000. |
| `successUrlContains` | no | Optional URL substring used as a success signal. |

When login succeeds, Core captures cookies/storage state and forwards the session into crawling, context probing, and fuzzing where supported by the bridge clients. If login fails, the current scan processor records the failure and continues unauthenticated.

---

## Reports

`reportFormat` accepts `html`, `json`, and `pdf`. It controls requested/generated report formats; file downloads are served through report-controller routes:

```text
GET /reports/:scanId
GET /reports/:scanId/download?format=html|json|pdf
GET /reports/:scanId/regenerate?formats=html,json,pdf
```

`GET /scan/:id/report` returns only:

```json
{ "reportUrl": "/reports/<id>.html" }
```

It is not the direct report file-download endpoint.

---

## Summary

| Core option | Naming | Notes |
|---|---|---|
| `maxParams` | camelCase | Core API request body. |
| `maxPayloadsPerParam` | camelCase | Core API request body. |
| `verifyExecution` | camelCase | Core API request body; bridge sends `verify_execution` to fuzzer. |
| `wafBypass` | camelCase | Core API request body. |
| `reportFormat` | camelCase | Core API request body. |
| `max_payloads` | snake_case | Payload-gen microservice request body only. |
| `verify_execution` | snake_case | Fuzzer microservice request body only. |
