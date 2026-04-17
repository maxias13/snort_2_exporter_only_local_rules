# Snort 2 vs Snort 3 Syntax Differences

This reference focuses on rule-writing differences that matter during migration.

## 1) Header Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| Traditional header | `action proto src_ip src_port -> dst_ip dst_port` | Same traditional form still supported | Usually retained unless service-header conversion is desired |
| Service header | Not native in classic Snort 2 style | `alert http (...)`, `alert dns (...)`, and others | Prefer service header when app protocol is known |
| File rules | Not first-class header type | `action file (...)` and `file_id (...)` | File-centric detections can be promoted to file rule types |
| Direction operators | `->`, `<>` | `->`, `<>` | No change |
| Negated destination variable | Commonly seen in legacy rulebases | Can be unsupported/problematic in target style | Replace with `any` when incompatible |

## 2) Action Vocabulary

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| IDS actions | `alert`, `log`, `pass` | `alert`, `log`, `pass` | No major change |
| IPS drop | `drop` | `block` and `drop` both exist in broader docs, but migration target maps to `block` | Convert `drop` to `block` for consistent migration policy |
| Silent drop | `sdrop` | Not used in Snort 3 migration style | Convert `sdrop` to `block` |
| Active responses | `reject`, `react`, `resp` usage patterns | `reject`, `react` supported with Snort 3 behavior | Validate deployment mode before preserving behavior |

## 3) Rule Body and Option Style

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| Option terminator | `;` | `;` | No change |
| Content modifiers | Often separate tokens after content (`content:"x"; nocase; fast_pattern;`) | Inline content option style (`content:"x",nocase,fast_pattern;`) | Rewrite modifier style inline |
| Relative/absolute modifiers | `offset:`, `depth:`, `distance:`, `within:` as separate options | Inline with content (`offset 2`, `within 20`) | Convert formatting and keep semantics |
| Metadata syntax | Commonly free-form one pair per metadata token | Metadata supports comma-separated key/value entries | Normalize metadata formatting |

## 4) Content Detection Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| Core `content` | Same keyword | Same keyword | Content survives but modifier format changes |
| `fast_pattern` usage | Standalone option or parameterized forms | Inline modifier with content | Convert to inline style |
| `nocase` usage | Standalone modifier after content | Inline with content | Convert to inline style |
| Negated content | `content:!"x";` | `content:!"x";` with inline modifiers possible | Keep negation, adjust style only |

## 5) Buffer Handling Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| HTTP buffer selection | Often used as content modifiers (`content:"x"; http_uri;`) | Sticky buffers set first (`http_uri; content:"x";`) | Reorder to sticky-buffer-first pattern |
| URI keyword | `uricontent` legacy keyword | Use `http_uri; content:` pattern | Replace every `uricontent` occurrence |
| Raw bytes handling | `rawbytes` content modifier | Sticky buffer model (`pkt_data;` or `raw_data;`) | Convert to sticky buffer keyword |
| Cursor reset | `pkt_data` exists | `pkt_data` remains and is central to sticky transitions | Add explicitly when returning from sticky buffers |

## 6) PCRE and Regex Model

| Topic | Snort 2 | Snort 3 | Migration Impact |
|---|---|---|---|
| PCRE option | `pcre:"/.../flags";` | Same general syntax | Keep pattern and standard flags |
| HTTP PCRE buffer flags | Legacy flags (`U`,`H`,`P`,`C`,`I`,`D`,`K`,`S`,`Y`) used to select buffers | Sticky buffers select context; legacy HTTP flags should be removed | Add sticky buffer then strip legacy buffer flag |
| Relative PCRE flag | `R` supported | `R` still meaningful | Preserve when logical |
| Alternate regex engine | Not standard in classic Snort 2 | Snort 3 introduces `regex` (Hyperscan-backed) | Optional optimization after successful migration |

## 7) New Keywords and Capabilities in Snort 3

| Area | Snort 3 Additions | Migration Relevance |
|---|---|---|
| Explicit service scoping | `service:http;` and other service values | Move service intent out of legacy metadata |
| Service headers | `alert http (...)` and similar | Candidate refactor for cleaner app-layer rules |
| Additional sticky buffers | Expanded HTTP and file-centric buffers | Enables more precise migrated rules |
| `regex` keyword | Hyperscan-backed regex option | Optional performance enhancement |
| File rule forms | `action file`, `file_id` | Useful for file signature migrations |

## 8) Removed or Deprecated Migration Targets

| Snort 2 Construct | Snort 3 Migration Direction |
|---|---|
| `uricontent` | Replace with `http_uri; content:` |
| HTTP buffer flags inside PCRE | Replace with sticky buffers before `pcre` |
| `sdrop` | Replace with `block` |
| Standalone content modifiers | Convert to inline content modifier style |
| Legacy service metadata usage | Use `service:` keyword |

## 9) Validation Checklist After Conversion

Use this quick checklist after transforming a rule:

1. Header is syntactically valid for Snort 3.
2. Action is valid and aligned with migration policy (`drop`/`sdrop` converted to `block`).
3. `uricontent` has been removed.
4. HTTP buffer modifiers were converted to sticky buffers.
5. `content` modifiers are inline.
6. Legacy PCRE HTTP buffer flags were removed and replaced with sticky buffers.
7. Destination negated variable incompatibilities were normalized to `any`.
8. Output rule keeps `sid` and `rev`.
9. Rule remains pure ASCII.
