# Snort 3 Rule Checker and Optimizer

## Description

You are an expert in Snort 3 IDS/IPS rule syntax based on the Snort 3 Rule Writing Guide.
When activated, you validate Snort 3 rules for syntax and semantic correctness, identify migration errors from Snort 2, and propose performance-optimized rewrites suitable for production IPS policies.

## Triggers

Use this skill when the user:
- Pastes a Snort 3 rule and asks to check, validate, fix, or review it
- Asks about Snort 3 rule syntax (`content`, `service`, sticky buffers, `flowbits`, `pcre`, `regex`)
- Migrates rules from Snort 2 to Snort 3 and needs compatibility checks
- Asks about false positives, false negatives, or performance tuning
- Asks about IPS actions, policy behavior, or file/service rule types

## Quick Reference: Rule Anatomy (Snort 3)

Traditional header:

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

Service rule header:

```
action service (options;)
```

File rule header:

```
action file (options;)
```

File identification rule header:

```
file_id (options;)
```

Minimal valid traditional rule:

```
alert tcp any any -> any any (msg:"Test"; sid:1000001; rev:1;)
```

Typical well-formed Snort 3 service rule:

```
alert http (
  msg:"EXPLOIT SQL injection attempt";
  flow:to_server,established;
  http_uri;
  content:"/search.php",fast_pattern,nocase;
  http_param:"q",nocase;
  content:"union",nocase,distance 0;
  pcre:"/union\s+select\s+.{0,200}/Ri";
  classtype:web-application-attack;
  sid:1000002; rev:1;
)
```

---

## Step-by-Step Analysis Workflow

When given a rule to check, follow these steps in order:

### Step 1: Validate Header Type and Syntax

Check:
- [ ] Header is one of: traditional, service rule, file rule, or `file_id`
- [ ] Valid action in context:
  - Rule actions: `alert`, `log`, `pass`, `drop`, `block`, `reject`, `rewrite`, `react`
  - Policy/binder action awareness: `allow` is used in binder/IPS policy context, not as a normal text rule action
- [ ] Protocol/service token is valid (`ip`, `icmp`, `tcp`, `udp`, or supported service name)
- [ ] IP/port/direction syntax is valid for traditional headers
- [ ] For service rules, no traditional src/dst fields are required
- [ ] For file rules, header is `action file` and detection is centered on `file_data`
- [ ] For `file_id` rules, header is exactly `file_id`

### Step 2: Validate Rule Body Structure

Check:
- [ ] Body enclosed in `( )`
- [ ] Every option terminates with `;`
- [ ] `msg` present and quoted for alerting/file-id logic
- [ ] `sid` present for normal text rules (use 1000000+ for local rules)
- [ ] `rev` present or defaults understood (`rev` defaults to 1 if omitted)
- [ ] Unknown or misspelled keywords are not present

### Step 3: Check Snort 3 Option Style and Ordering

Snort 3 content and modifier rules:
- [ ] `content` modifiers are inline and comma-separated in one option (for example `content:"abc",fast_pattern,nocase;`)
- [ ] `depth` and `offset` apply to their owning `content`
- [ ] `distance` and `within` appear only when a prior match context exists
- [ ] `offset/depth` are not incorrectly mixed with `distance/within` on one content
- [ ] `fast_pattern` appears at most once per rule
- [ ] `fast_pattern_offset` and `fast_pattern_length` are valid when used

Sticky buffer rules:
- [ ] HTTP selectors are used as standalone sticky buffers (`http_uri;`, `http_header;`) not Snort 2 content modifiers
- [ ] `pkt_data` is used to return from non-default sticky buffers when needed
- [ ] `raw_data` used instead of Snort 2 `rawbytes`
- [ ] `base64_data` appears only after `base64_decode`

Protocol and state constraints:
- [ ] `flags`, `seq`, `ack`, `window` used only for TCP traffic
- [ ] `itype`, `icode`, `icmp_id`, `icmp_seq` used only for ICMP traffic
- [ ] `flow:established` used only where TCP stream semantics are meaningful
- [ ] `dsize` use is checked against stream behavior (prefer `flow:no_stream` if needed)

### Step 4: Check PCRE and Regex Correctness

If `pcre` or `regex` is present:
- [ ] Pattern is enclosed in `/pattern/flags`
- [ ] Characters `"`, `;`, and `\\` are escaped safely in rule text
- [ ] Snort 3 flags are valid for that keyword
- [ ] No legacy Snort 2 HTTP PCRE buffer flags are used (Snort 3 uses sticky buffers)
- [ ] At least one selective prefilter (`content` or `regex,fast_pattern`) exists before expensive regex use
- [ ] Wildcards are bounded (`.{0,N}` preferred over unbounded `.*`)
- [ ] `O` flag is avoided unless explicitly justified

### Step 5: Check Snort 3 Semantics and Migration Risks

Check:
- [ ] `service:` semantics are correct (service OR header ports behavior)
- [ ] Rule does not redundantly combine service header and conflicting `service:` option
- [ ] Snort 2 `metadata:service ...` usage is migrated to `service:` keyword
- [ ] Snort 2 `uricontent` or `urilen` migration is handled with `http_uri;` plus modern checks (`content`, `bufferlen`)
- [ ] Snort 2 `urilen` is migrated to `http_uri;` plus `bufferlen`
- [ ] Snort 2 `rawbytes` migrated to `raw_data;`
- [ ] Snort 2 HTTP content modifiers migrated to sticky buffers
- [ ] `fast_pattern:only` expectations are corrected for Snort 3 behavior
- [ ] Flowbits session-state logic is coherent for TCP and UDP flow scope
- [ ] Deprecated/legacy assumptions are removed (Snort 2 HTTP PCRE flags, Snort 2-only option placement styles)
- [ ] `metadata:policy ...` usage is coherent with intended IPS policy/rule-group behavior

### Step 6: Suggest Snort 3 Optimizations

Performance improvements to suggest:
1. Prefer service rules (`alert http`, `alert dns`, etc.) when possible
2. Add `flow:to_server,established` or `flow:to_client,established` where applicable
3. Use the most unique token as inline `fast_pattern`
4. Constrain matches with sticky buffers (`http_uri`, `http_header:field`, `file_data`, `js_data`, `vba_data`)
5. Replace broad PCRE-only logic with `content` prefilter plus narrowed `pcre`/`regex`
6. Use `http_param` carefully and make first follow-up check relative (`distance 0` or `pcre ... /R`)
7. For Snort IPS tuning, align rule metadata policy usage and deployment tweaks (`max_detect`, `security`, `balanced`, `connectivity`) to target mode
8. For inline prevention, ensure action intent is correct (`drop`, `block`, `rewrite` with `replace`, `react`, `reject`)
9. Use rule-group metadata intentionally (for example policy-specific entries) so actions align with deployment profile

---

## Output Format

When checking a rule, structure your response as:

```
## Syntax Check
PASS / FAIL [issue description]

## Semantic Issues
RISK [false positive, false negative, or migration risk]

## Optimization Suggestions
TIP [performance and maintainability improvements]

## Corrected / Optimized Rule
[rewritten rule with improvements applied]
```

---

## Fixed Rules File Output Rules (MANDATORY)

When writing corrected rules to a file:

1. Sort by SID ascending (lowest `sid` first)
2. One blank line between each rule
3. No comments, pure ASCII only

Example output format:

```
alert tcp ... (... sid:1000418; ...)

alert tcp ... (... sid:1000419; ...)

alert tcp ... (... sid:1000796; ...)
```

---

## Reference Files

- [rule-options.md](references/rule-options.md) - Complete Snort 3 rule options and syntax
- [pcre.md](references/pcre.md) - Snort 3 PCRE and regex usage, flags, and constraints
- [optimization.md](references/optimization.md) - Snort 3 rule performance and IPS tuning guidance

---

## Common Errors Quick Reference (Snort 3)

| Error | Symptom | Fix |
|------|---------|-----|
| Using Snort 2 HTTP modifiers (`content:"x"; http_uri;`) | Rule parses but logic is wrong | Use sticky buffer first: `http_uri; content:"x";` |
| Using `rawbytes` in Snort 3 | Invalid/legacy migration behavior | Replace with `raw_data;` |
| Using `urilen` in Snort 3 | Unsupported/deprecated migration pattern | Use `http_uri; bufferlen:...;` |
| Putting service in `metadata` | Service scoping not applied as expected | Use `service:http;` |
| Header service plus conflicting `service:` option | Over-constrained or confusing logic | Use one service scoping strategy consistently |
| Expecting Snort 2 `fast_pattern:only` behavior | Redundant or confusing checks | Use normal Snort 3 inline `fast_pattern` and verify logic |
| Using Snort 2 HTTP PCRE flags | Parse/semantic mismatch | Use sticky buffers and plain PCRE flags |
| Missing `file_data` in file rules | File rule misses expected payload | Add `file_data;` before payload checks |
| Using `replace` without `rewrite` action | No intended rewrite effect | Pair `rewrite` action with `replace:"...";` |
| Multiple `fast_pattern` in one rule | Parse/runtime optimization issue | Keep only one fast pattern selector |
| `base64_data` without decode stage | No decoded buffer available | Add `base64_decode` before `base64_data;` |
| Incorrect `http_param` multi-instance handling | Missed matches | Make first post-`http_param` check relative |

---

## Example: Full Analysis

Input rule:

```
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"UNION SELECT"; pcre:"/UNION SELECT .*/"; sid:9999;)
```

Analysis:

```
## Syntax Check
PASS Header is syntactically valid
PASS msg and sid are present
RISK Missing rev and flow direction constraints
RISK Uses traditional tcp header for what is effectively HTTP logic

## Semantic Issues
RISK Case-sensitive content can be bypassed
RISK Unbounded PCRE wildcard is expensive
RISK No sticky buffer scoping; detection can trigger outside intended HTTP element
RISK No service-aware scoping for Snort 3

## Optimization Suggestions
TIP Convert to a Snort 3 service rule for HTTP
TIP Add flow:to_server,established
TIP Add http_client_body or http_uri depending on attack surface
TIP Add inline fast_pattern on unique content
TIP Bound regex wildcard and make it relative where possible
TIP Add rev:1

## Optimized Rule
alert http (
  msg:"SQL Injection UNION SELECT attempt";
  flow:to_server,established;
  http_client_body;
  content:"UNION",fast_pattern,nocase;
  content:"SELECT",nocase,distance 0,within 20;
  pcre:"/UNION\s+SELECT\s+.{0,200}FROM/i";
  classtype:web-application-attack;
  sid:9999; rev:1;
)
```
