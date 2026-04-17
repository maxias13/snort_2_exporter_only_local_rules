# Snort 3 PCRE and Regex Reference

## 1) Snort 3 Regular Expression Options

Snort 3 has two regex-capable rule options:

- `pcre` - Perl Compatible Regular Expressions evaluated by PCRE engine
- `regex` - Hyperscan-backed regular expressions (when hyperscan is enabled)

## 2) `pcre` Syntax

```
pcre:[!]"/pattern/flags";
```

- `!` negates match
- Pattern must be enclosed in `/.../`
- Flags appear after final `/`
- Evaluates against current sticky buffer in Snort 3

### Supported `pcre` flags in the guide

| Flag | Meaning |
|------|---------|
| `i` | case-insensitive |
| `s` | dot matches newline |
| `m` | multiline anchors behavior |
| `x` | ignore unescaped whitespace in pattern |
| `A` | anchor at start of buffer |
| `E` | strict end-of-string behavior for `$` |
| `G` | invert greediness defaults |
| `O` | override pcre match limits (use sparingly) |
| `R` | start search from end of last match (relative mode) |

Important Snort 3 difference:
- Snort 3 no longer uses Snort 2 HTTP-specific PCRE buffer flags. Use sticky buffers (`http_uri;`, `http_header;`, etc.) before `pcre`.

## 3) `regex` Syntax

```
regex:"/pattern/flags"[,fast_pattern][,nocase];
```

- Evaluates against current sticky buffer
- Can be used with `fast_pattern`
- Requires hyperscan search engine support and config

Hyperscan-related configuration example:

```
search_engine = { search_method = "hyperscan" }
```

### Supported `regex` flags in the guide

| Flag | Meaning |
|------|---------|
| `i` | case-insensitive |
| `s` | dot matches newline |
| `m` | multiline anchors behavior |
| `R` | start from end of previous match |

## 4) Escaping Rules in Snort Rule Text

Because Snort rule options use quoted strings, safely escape special characters in patterns.

Common escaped bytes used in rule patterns:

| Character | Safe representation |
|-----------|---------------------|
| `"` | `\x22` |
| `;` | `\x3b` |
| `\\` | `\x5c` |

## 5) Sticky Buffer Behavior with Regex

Regex checks run in the current cursor/buffer context.

Examples:

```
http_uri;
pcre:"/[?&]cmd=[^&]{1,100}/i";
```

```
http_header:field user-agent;
regex:"/python-requests\/[0-9.]+/i",fast_pattern;
```

```
file_data;
pcre:"/\x4d\x5a.{0,200}\x50\x45/s";
```

## 6) Relative Matching (`R`) Guidance

- Use `R` when the regex should start from the prior match position.
- Especially useful after `http_param` where first post-option check should be relative.

Example:

```
http_param:"user",nocase;
pcre:"/([\x27\x22\x3b\x23]|\x2d\x2d)/R";
```

## 7) Performance Best Practices

1. Always prefilter with selective `content` (or a selective `regex,fast_pattern`) before expensive regex checks.
2. Bound wildcards: prefer `.{0,200}` over unbounded `.*`.
3. Anchor when possible (`A` or explicit `^`).
4. Use sticky buffers to reduce search space (`http_uri`, `http_header:field`, `file_data`).
5. Avoid `O` unless absolutely required.
6. Do not attempt Snort 2 HTTP PCRE flag migration directly; use Snort 3 sticky buffers.

## 8) Common Snort 3 Regex Mistakes

| Mistake | Symptom | Fix |
|--------|---------|-----|
| Using Snort 2 HTTP PCRE flags | Invalid or wrong buffer behavior | Replace with sticky buffers |
| No prefilter before heavy regex | High CPU | Add selective `content`/`fast_pattern` |
| Unbounded `.*` near ambiguous text | Backtracking cost | Use bounded quantifiers |
| Missing delimiters `/.../` | Parse failure | Add proper regex delimiters |
| `base64_data` regex without decode | No decoded buffer | Add `base64_decode` first |
| Not using relative mode where needed | Missed multi-instance matches | Add `R` or relative content modifiers |

## 9) Snort 2 vs Snort 3 Regex Migration Notes

- Snort 2: many HTTP buffer selectors were packed into PCRE flags.
- Snort 3: buffer is selected with standalone sticky keywords first.
- Snort 3 introduces `regex` option (hyperscan) which can participate in fast-pattern selection.
