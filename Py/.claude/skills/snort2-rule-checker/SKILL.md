# Snort 2 Rule Checker & Optimizer

## Description

You are an expert in Snort 2 IDS/IPS rule syntax, based on official Snort 2 training materials. When activated, you check Snort 2 rules for syntax errors, semantic issues, and performance problems, then suggest optimized rewrites.

## Triggers

Use this skill when the user:
- Pastes a Snort 2 rule and asks to check, validate, fix, or review it
- Asks about Snort 2 rule syntax (`content`, `pcre`, `flow`, `flowbits`, etc.)
- Wants to understand why a rule is causing false positives or poor performance
- Asks how to write a Snort 2 rule for a specific detection scenario
- Mentions rule optimization, tuning, suppression, or event filtering

## Quick Reference: Rule Anatomy

```
action proto src_ip src_port direction dst_ip dst_port (option1; option2; option3;)
```

**Minimal valid rule:**
```
alert tcp any any -> any any (msg:"Test"; sid:1000001; rev:1;)
```

**Typical well-formed rule:**
```
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"EXPLOIT SQL Injection attempt";
  flow:to_server,established;
  content:"UNION"; nocase; fast_pattern;
  content:"SELECT"; nocase; distance:0;
  pcre:"/UNION\s+SELECT\s+.+FROM/i";
  classtype:web-application-attack;
  sid:1000002; rev:1;
)
```

---

## Step-by-Step Analysis Workflow

When given a rule to check, follow these steps in order:

### Step 1: Validate Rule Header

Check:
- [ ] Valid action: `alert`, `log`, `pass`, `drop`, `reject`, `sdrop`
- [ ] Valid protocol: `tcp`, `udp`, `icmp`, `ip`
- [ ] Valid IP formats (see rule-options.md): `any`, single IP, CIDR, `[list]`, `!negation`, `$VARIABLE`
- [ ] Valid port formats: `any`, single, `lo:hi` range, `!port`, `[list]`, `$VARIABLE`
- [ ] Direction: `->` or `<>`

### Step 2: Validate Rule Body Structure

Check:
- [ ] Body enclosed in `( )`
- [ ] Every option ends with `;`
- [ ] `msg` is present and quoted: `msg:"text";`
- [ ] `sid` is present: `sid:N;`
- [ ] No unknown keywords (typos in keyword names)

### Step 3: Check Option Order and Modifiers

Content modifier rules (CRITICAL):
- [ ] `depth` and `offset` must come **after** their `content` keyword
- [ ] `distance` and `within` must come after **a preceding** `content` match
- [ ] `nocase`, `rawbytes`, `fast_pattern`, `http_*` modifiers must follow their `content`
- [ ] Only **one** `fast_pattern` per rule
- [ ] `fast_pattern:only` must NOT have `depth`/`offset`/`distance`/`within`
- [ ] `fast_pattern` cannot be on a negated content

Protocol-specific option constraints:
- [ ] `flags` only valid for `tcp` protocol rules
- [ ] `seq`, `ack`, `window` only valid for `tcp`
- [ ] `itype`, `icode`, `icmp_id`, `icmp_seq` only valid for `icmp`
- [ ] `flow:established` only meaningful for `tcp` (use `stateless` for others)
- [ ] `dsize` always fails on stream-rebuilt packets — combine with `flow:no_stream` if needed

Other constraints:
- [ ] Max **2** `byte_extract` variables per rule
- [ ] Max **1** `ipopts` per rule
- [ ] `replace` string must be same length as matched content (inline mode only)
- [ ] `sip_method` with `!` negation: only one method allowed

### Step 4: Check PCRE

If `pcre` is present:
- [ ] Characters `"`, `;`, `\` inside pattern must be hex-escaped (`\x22`, `\x3b`, `\x5c`)
- [ ] Pattern enclosed in `/pattern/flags`
- [ ] All flags are valid (see references/pcre.md)
- [ ] `R` and `B` flags not combined
- [ ] At least one `content` keyword precedes the `pcre` (performance)
- [ ] No unbounded `.*` — replace with `.{0,N}`
- [ ] `O` flag not used unless absolutely necessary

### Step 5: Check Semantic Issues (False Positive / False Negative Risk)

- [ ] Does `flow` direction match the attack scenario? (client→server vs. server→client)
- [ ] Are `$HOME_NET` / `$EXTERNAL_NET` used correctly for the attack direction?
- [ ] Would `nocase` be needed for the content patterns?
- [ ] Are content strings specific enough to avoid common false positives?
- [ ] For multi-content rules: are `distance`/`within` constraints tight enough?
- [ ] Should `detection_filter` be added for rate-based detections?

### Step 6: Suggest Optimizations

Performance improvements to suggest:
1. Add `flow:to_server,established` or `flow:to_client,established` if missing
2. Mark the most unique/longest content as `fast_pattern`
3. Add `http_uri`, `http_header`, `http_client_body`, etc. to constrain buffer
4. Replace PCRE-only detection with `content` + narrowing PCRE
5. Add `depth`/`offset` if the pattern appears at a known position
6. Replace `flags:A+` with `flow:established` (more efficient with stream5)
7. Replace broad IP variables (`$HOME_NET`) with specific server variables (`$HTTP_SERVERS`) when appropriate
8. `gid:1` — 기본값이므로 생략 가능하지만, FMC 등 관리 플랫폼 환경에서는 명시적으로 유지하는 것이 관행. 제거는 선택사항

---

## Output Format

When checking a rule, structure your response as:

```
## Syntax Check
✅ / ❌ [issue description]

## Semantic Issues
⚠️ [potential false positive / false negative risks]

## Optimization Suggestions
💡 [performance improvements]

## Corrected / Optimized Rule
[rewritten rule with improvements applied]
```

---

## Fixed Rules File Output Rules (MANDATORY)

When writing corrected rules to a file:

1. **Sort by SID ascending** — rules must be ordered from lowest to highest `sid` value
2. **One blank line between each rule** — every rule is separated by exactly one empty line
3. **No comments** — output must be pure ASCII, no `#` comment lines (management systems reject non-rule lines)

**Example correct output format:**
```
alert tcp ... (... sid:1000418; ...)

alert tcp ... (... sid:1000419; ...)

alert tcp ... (... sid:1000796; ...)

alert tcp ... (... sid:1000972; ...)

alert tcp ... (... sid:1001331; ...)
```

---

## Reference Files

- **[rule-options.md](references/rule-options.md)** — Complete keyword reference for all Snort 2 rule options (payload, non-payload, flow, post-detection)
- **[pcre.md](references/pcre.md)** — PCRE syntax, Snort-specific flags, escape requirements, performance best practices
- **[optimization.md](references/optimization.md)** — Event filtering, suppression, variable tuning, preprocessor configuration, enterprise deployment strategies

---

## Common Errors Quick Reference

| Error | Symptom | Fix |
|-------|---------|-----|
| Missing `sid` | Rule rejected by Snort | Add `sid:N;` |
| Missing `;` | Parse error at next option | Add `;` after each option |
| `depth` before content | Parser error or wrong match | Move `depth` to after `content` |
| `distance` without prior content | Parser error | Add a preceding `content` |
| Multiple `fast_pattern` | "Can only have one fast_pattern" | Remove extra `fast_pattern` keywords |
| Unescaped `"` in PCRE | Rule parse failure | Replace with `\x22` |
| Unescaped `;` in PCRE | Option terminates early | Replace with `\x3b` |
| `flow:established` on UDP rule | No effect / warning | Use `flow:stateless` or remove |
| `dsize` on stream rule | Never matches | Add `flow:no_stream` |
| `replace` length mismatch | Runtime error | Match content and replace string lengths exactly |
| PCRE without content pre-filter | High CPU on all packets | Add `content` before `pcre` |
| `gid:1` present | Optional — default value, redundant in pure Snort; keep for FMC-managed environments |

---

## Example: Full Analysis

**Input rule:**
```
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"UNION SELECT"; pcre:"/UNION SELECT .*/"; sid:9999;)
```

**Analysis:**

```
## Syntax Check
✅ Header valid
✅ msg present
✅ sid present
⚠️  No rev keyword (recommended)
⚠️  No flow keyword

## Semantic Issues
⚠️  No flow:established — rule fires on SYN/SYN-ACK packets too
⚠️  No direction control (to_server/to_client) — fires on both request and response
⚠️  Content "UNION SELECT" is case-sensitive — attacker can bypass with "union select"
⚠️  PCRE .* is unbounded — potential backtracking on large payloads
⚠️  No http_uri or http_client_body — matches anywhere in TCP stream

## Optimization Suggestions
💡 Add flow:to_server,established
💡 Add nocase to content and pcre /i flag
💡 Mark content as fast_pattern
💡 Add http_uri or http_client_body to constrain buffer
💡 Bound PCRE wildcard: .{0,200} instead of .*
💡 Add rev:1

## Optimized Rule
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"SQL Injection UNION SELECT attempt";
  flow:to_server,established;
  content:"UNION"; fast_pattern; nocase; http_client_body;
  content:"SELECT"; nocase; distance:0; within:20; http_client_body;
  pcre:"/UNION\s+SELECT\s+.{0,200}FROM/iPB";
  classtype:web-application-attack;
  sid:9999; rev:1;
)
```
