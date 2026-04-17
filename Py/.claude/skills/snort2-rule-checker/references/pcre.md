# Snort 2 PCRE Reference

## Basic Syntax

```
pcre:[!]"/pattern/flags";
```

- Pattern must be enclosed in `/`
- Negation `!` inverts match (alert if pattern does NOT match)
- Flags follow the closing `/`

## Standard PCRE Flags (Perl-compatible)

| Flag | Meaning |
|------|---------|
| `i` | Case-insensitive matching |
| `s` | Dot `.` matches any character including newline |
| `m` | `^` and `$` match at embedded newlines (multiline) |
| `x` | Ignore unescaped whitespace and `#` comments in pattern |
| `A` | Anchor match at start of buffer (same as `^`) |
| `E` | `$` matches only at end of string (not before final newline) |
| `G` | Invert greediness (make `*` lazy, `*?` greedy) |

## Snort-Specific PCRE Flags (Buffer Selection)

These flags control **which buffer** the PCRE matches against:

| Flag | Buffer | Equivalent Keyword |
|------|--------|--------------------|
| `R` | Relative to end of last `content` match | same as `distance:0` |
| `U` | Normalized HTTP request URI | same as `uricontent` |
| `I` | Unnormalized HTTP request URI | similar to `http_raw_uri` |
| `H` | Normalized HTTP request/response header | similar to `http_header` |
| `D` | Unnormalized HTTP request/response header | similar to `http_raw_header` |
| `M` | Normalized HTTP request method | similar to `http_method` |
| `P` | Normalized HTTP request body | similar to `http_client_body` |
| `C` | Normalized HTTP cookie | similar to `http_cookie` |
| `K` | Unnormalized HTTP cookie | similar to `http_raw_cookie` |
| `S` | HTTP response status code | similar to `http_stat_code` |
| `Y` | HTTP response status message | similar to `http_stat_msg` |
| `B` | Do not use decoded buffers (raw bytes) | same as `rawbytes`; **do not combine with `R`** |
| `O` | Override configured PCRE match limit | use with caution — performance impact |

## Characters That Must Be Hex-Escaped in PCRE Patterns

These characters have special meaning in Snort rule syntax and must be escaped:

| Character | Hex Escape | Reason |
|-----------|-----------|--------|
| `"` | `\x22` | Closes the rule option string |
| `;` | `\x3b` | Ends the rule option |
| `\` | `\x5c` | Escape character itself |

## PCRE Best Practices

### Performance Rules

1. **Always pair PCRE with a preceding `content` match.** The fast-pattern engine pre-filters packets — PCRE only runs on packets that already matched a content. Without content, PCRE runs on every packet.

   ```
   # GOOD: content pre-filters, PCRE refines
   content:"SELECT"; nocase; pcre:"/SELECT\s+.+FROM/i";
   
   # BAD: PCRE runs on every TCP packet
   pcre:"/SELECT\s+.+FROM/i";
   ```

2. **Use PCRE as last resort.** If a `content` match can fully express the detection, skip PCRE entirely.

3. **Avoid catastrophic backtracking.** Patterns like `(a+)+` or `(.+)*` can cause exponential time on crafted input. Use possessive quantifiers or atomic groups where needed.

4. **Minimize wildcard scope.** Use `.{0,50}` instead of `.*` to bound the search space.

5. **Prefer anchored patterns.** Use `A` flag or `^` to anchor at buffer start when possible.

6. **Avoid the `O` flag in production.** Overriding the PCRE match limit can stall the engine on adversarial input.

### Common Patterns

```
# Case-insensitive match anywhere in URI
pcre:"/cmd\.exe/Ui";

# Match relative to previous content match
content:"User-Agent:"; pcre:"/[Mm]ozilla\x2f[\d\.]+/R";

# Match shell metacharacters in POST body
content:"POST"; http_method; pcre:"/[;&|`$(){}].*(\bwget\b|\bcurl\b)/Pi";

# SQL injection pattern
content:"'"; pcre:"/'\s*(or|and)\s+[\w'\"]+\s*[=<>]/i";

# Base64-encoded payload detection
content:"Content-Transfer-Encoding:"; pcre:"/base64/Hi";
```

### Flag Combinations

```
# HTTP URI, case-insensitive, anchored
pcre:"/^\/admin\//UAi";

# Relative to last content, case-insensitive
content:"Authorization:"; pcre:"/Basic\s+[A-Za-z0-9+\/=]{20,}/Ri";

# Raw bytes (bypass normalization)
pcre:"/\x2f\x2e\x2e\x2f/B";
```

## Common PCRE Syntax Errors in Snort Rules

| Error | Fix |
|-------|-----|
| Unescaped `"` inside pattern | Replace with `\x22` |
| Unescaped `;` inside pattern | Replace with `\x3b` |
| Unescaped `\` at end of group | Replace with `\x5c` |
| Missing closing `/` before flags | Add `/flags"` |
| `R` flag combined with `B` flag | Not valid; `R` uses decoded buffer, `B` forces raw |
| PCRE without any preceding content | Add at least one `content` keyword before `pcre` |
| `O` flag in production rule | Remove — PCRE match limit exists to prevent DoS |
| Pattern with unbounded `.*` | Replace with `.{0,N}` to bound backtracking |
