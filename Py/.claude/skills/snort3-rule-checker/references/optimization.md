# Snort 3 Rule Optimization and Tuning Reference

## 1) Performance Fundamentals in Snort 3

Snort 3 performance depends on:
- Fast-pattern quality
- Correct service scoping
- Sticky buffer precision
- Avoiding expensive generic regex on broad traffic
- Matching rule design to IPS policy mode and deployment intent

## 2) Fast Pattern Strategy

### How Snort 3 handles fast pattern

- Snort selects a fast pattern automatically if none is specified
- You can force selection with inline `fast_pattern` content modifier
- You can select a substring with `fast_pattern_offset` and `fast_pattern_length`
- Snort 3 can skip re-evaluation of fast-pattern content when possible (behavior changed from Snort 2 expectations)

### Good fast pattern design

1. Pick unique, stable tokens
2. Avoid very short/common strings
3. Put fast pattern in the correct sticky buffer
4. Confirm fast-pattern eligibility for chosen buffer

### Fast-pattern caveats from guide

Certain buffers are not eligible for fast-pattern content selection, including:
- `http_raw_cookie`
- `http_param`
- `http_raw_body`
- `http_version`
- `http_raw_request`
- `http_raw_status`
- `http_raw_trailer`
- `http_true_ip`

Example:

```
http_uri;
content:"/admin/panel.php",fast_pattern,nocase;
content:"cmd=",nocase;
```

## 3) Sticky Buffer Optimization

Snort 3 relies heavily on sticky buffers. Use the narrowest correct buffer:

- URI attacks: `http_uri` or `http_raw_uri`
- Header checks: `http_header` or `http_header:field <name>`
- Cookie checks: `http_cookie` or `http_raw_cookie`
- Body checks: `http_client_body` or `http_raw_body`
- File payload checks: `file_data`
- JavaScript logic checks: `js_data`
- VBA macro checks: `vba_data`

Benefits:
- Lower false positives
- Smaller search domain
- Better CPU behavior

Migration warning:
- Do not use Snort 2-style HTTP content modifiers. In Snort 3 these are sticky buffer keywords.

## 4) Service and Header Design Choices

### Prefer service-rule headers when practical

Use service rule style to bind detection to app-level traffic:

```
alert http (...)
```

This avoids brittle port assumptions and improves semantic accuracy.

### Use `service:` option when needed

`service:` can broaden applicability with service-or-port behavior relative to traditional headers.
Do not mix header service declarations and `service:` option without clear reason.

## 5) Rule Type Optimization

### Service rules
- Best when detection is app-protocol specific regardless of ports

### File rules
- Use `action file` plus `file_data`
- Best for file payload signatures across HTTP/SMTP/POP3/IMAP/SMB/FTP data paths

### File identification rules (`file_id`)
- Use `file_meta` and `file_data`
- Define reusable file-type context for later `file_type` constraints

## 6) Content and Cursor Efficiency

1. Place selective content early
2. Use `offset`/`depth` for absolute constraints
3. Use `distance`/`within` for tight relative chaining
4. Use `bufferlen`, `isdataat`, and byte operations for exactness
5. Keep first condition after `http_param` relative (`distance 0` or `pcre ... /R`) to avoid missing repeated parameter keys

## 7) Regex and PCRE Optimization

1. Add selective prefilters before `pcre`
2. Bound regex quantifiers (`.{0,N}`)
3. Use sticky buffers before regex; do not depend on Snort 2 PCRE HTTP flags
4. Use hyperscan-backed `regex` with `fast_pattern` where appropriate and available
5. Avoid `O` unless you have measured and justified the need

## 8) Flow and Session-State Optimization

Use flow gating:
- `flow:to_server,established;` for request-side app checks
- `flow:to_client,established;` for response-side checks
- `flow:stateless;` only when needed

Use `flowbits` to model multi-step behavior safely:
- setter rule(s) with `flowbits:set,...; flowbits:noalert;`
- checker rule(s) with `flowbits:isset,...;`

Snort 3 flowbits scope applies across transport sessions (TCP/UDP flow tracking context).

## 9) Post-Detection Tuning

### detection_filter

Require repeated hits before event generation:

```
detection_filter:track by_src,count 30,seconds 60;
```

Use to reduce bursty false-positive alert volume.

### tag

Capture follow-on packets/bytes/seconds after event for triage.

### rewrite + replace

Use when inline payload rewrite is intended.

## 10) IPS Policy and Deployment Tuning

Snort 3 offers tweak policies to bias toward security or performance:
- `max_detect` (most security-focused)
- `security`
- `balanced`
- `connectivity` (most performance/uptime-oriented)
- `talos` (Talos testing-style profile)

Command-line example:

```
snort -c snort.lua -R local.rules --tweaks max_detect
```

Operational guidance:
- High-risk perimeter: prefer stronger detect profiles
- Throughput-sensitive internal links: evaluate balanced/connectivity tradeoff
- Validate rules under the same tweak profile used in production

## 11) Binder and Inspector Routing Optimization

Binder determines inspector routing. Correct binder entries reduce misclassification and wasted processing.

Common patterns:
- bind known services to expected ports/roles
- allow wizard fallback for unknown service discovery
- avoid over-broad bindings that force expensive inspectors unnecessarily

## 12) Useful Validation and Debug Workflow

1. Validate config and rules
2. Test with representative pcaps
3. Use trace modules for:
   - rule evaluation tracing
   - buffer dumps
   - fast-pattern search insight
   - wizard/service detection visibility
4. Re-tune content/flow/buffers based on observed misses/noise

Trace examples in guide include:
- `trace.modules.detection.fp_search`
- `trace.modules.detection.buffer`
- `trace.modules.detection.rule_eval`
- `trace.modules.wizard`

## 13) Common Snort 3 Optimization Anti-Patterns

| Anti-pattern | Impact | Better approach |
|-------------|--------|-----------------|
| Broad tcp rule with no service/buffer constraints | High CPU, high noise | Use service rule and sticky buffer |
| PCRE-first detection without selective content | Costly evaluation | Add selective fast-pattern content first |
| Snort 2 HTTP modifier syntax in Snort 3 | Wrong logic | Use standalone sticky buffers |
| Using `service` in metadata | Service scoping lost | Use explicit `service:` option |
| Ignoring `http_param` relative guidance | Missed matches | First post-`http_param` check relative |
| Using ineligible fast-pattern buffers | No expected acceleration | Move fast pattern to eligible buffer |
| Overusing `flow:stateless` | More packets evaluated | Use established directional flow where possible |
| Failing to align policy tweak with production | Test/prod mismatch | Test with target `--tweaks` profile |
