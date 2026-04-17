# Deprecated Snort 2 Options and Snort 3 Replacements

This reference lists Snort 2 keywords and patterns that are deprecated, removed, or migration-sensitive when moving to Snort 3 rule style.

## Migration Mapping Table

| Snort 2 Keyword or Pattern | Status in Snort 3 Migration | Snort 3 Replacement or Handling | Notes |
|---|---|---|---|
| `uricontent:"...";` | Deprecated migration pattern | `http_uri; content:"...";` | Always convert to sticky-buffer form |
| `uricontent:!"...";` | Deprecated migration pattern | `http_uri; content:!"...";` | Preserve negation intent |
| `content:"..."; http_uri;` | Snort 2 modifier style | `http_uri; content:"...";` | Sticky buffer must come first |
| `content:"..."; http_header;` | Snort 2 modifier style | `http_header; content:"...";` | Same conversion pattern |
| `content:"..."; http_client_body;` | Snort 2 modifier style | `http_client_body; content:"...";` | Same conversion pattern |
| `content:"..."; http_raw_uri;` | Snort 2 modifier style | `http_raw_uri; content:"...";` | Same conversion pattern |
| `content:"..."; http_cookie;` | Snort 2 modifier style | `http_cookie; content:"...";` | Same conversion pattern |
| `content:"..."; http_raw_cookie;` | Snort 2 modifier style | `http_raw_cookie; content:"...";` | Same conversion pattern |
| `content:"..."; http_method;` | Snort 2 modifier style | `http_method; content:"...";` | Same conversion pattern |
| `content:"..."; http_stat_code;` | Snort 2 modifier style | `http_stat_code; content:"...";` | Same conversion pattern |
| `content:"..."; http_stat_msg;` | Snort 2 modifier style | `http_stat_msg; content:"...";` | Same conversion pattern |
| `rawbytes;` | Deprecated modifier style | `pkt_data;` | Use sticky buffer per migration requirement |
| `fast_pattern;` as standalone | Style change required | `content:"...",fast_pattern;` | Attach inline to owning content |
| `nocase;` as standalone | Style change required | `content:"...",nocase;` | Attach inline to owning content |
| `depth:N;` as separate option | Style change required | `content:"...",depth N;` | Keep semantics |
| `offset:N;` as separate option | Style change required | `content:"...",offset N;` | Keep semantics |
| `distance:N;` as separate option | Style change required | `content:"...",distance N;` | Keep semantics |
| `within:N;` as separate option | Style change required | `content:"...",within N;` | Keep semantics |
| `drop` action | Migration policy change | `block` | Map for Snort 3 target profile |
| `sdrop` action | Deprecated/removed in migration style | `block` | No direct `sdrop` equivalent in target output |
| `metadata: service http;` | Legacy service declaration style | `service:http;` | Use explicit keyword |
| `!$VARIABLE` in destination IP | Compatibility issue in target style | destination IP `any` | Preserve detection by widening destination |

## PCRE Flag Migration (Critical)

Snort 2 commonly used HTTP buffer selectors inside PCRE flags. In Snort 3 migration style, select sticky buffer first and remove buffer flags from `pcre`.

| Snort 2 PCRE Flag | Meaning in Snort 2 | Snort 3 Handling |
|---|---|---|
| `U` | normalized URI buffer | Add `http_uri;` before `pcre`, then remove `U` |
| `H` | normalized header buffer | Add `http_header;` before `pcre`, then remove `H` |
| `P` | normalized request body | Add `http_client_body;` before `pcre`, then remove `P` |
| `C` | cookie buffer | Add `http_raw_cookie;` before `pcre`, then remove `C` |
| `I` | raw URI buffer | Add `http_raw_uri;` before `pcre`, then remove `I` |
| `D` | raw header buffer | Add `http_raw_header;` before `pcre`, then remove `D` |
| `K` | raw cookie buffer variant | Add `http_raw_cookie;` before `pcre`, then remove `K` |
| `S` | HTTP status code buffer | Add `http_stat_code;` before `pcre`, then remove `S` |
| `Y` | HTTP status message buffer | Add `http_stat_msg;` before `pcre`, then remove `Y` |

### PCRE migration example

- Snort 2: `pcre:"/login\.php/iU";`
- Snort 3: `http_uri; pcre:"/login\.php/i";`

## dsize and Stream Caveat

| Snort 2 Pattern | Risk | Snort 3 Migration Guidance |
|---|---|---|
| `dsize` without stream-awareness | Can fail or misbehave on stream-rebuilt payload logic | Keep `dsize` only when semantics are packet-size based; review with `flow:no_stream` when needed |

`dsize` should be treated as manual-review-sensitive during migration if the original rule clearly depended on stream reconstruction.

## flags: Caveat in Modern Migration

| Snort 2 Pattern | Risk | Snort 3 Migration Guidance |
|---|---|---|
| `flags:A+;` used as established-flow proxy | Can be less precise and less maintainable | Prefer explicit flow gating such as `flow:to_server,established;` when behavior intent is stream state |

Preserve `flags` checks only if packet-level TCP flag semantics are truly intended.

## Legacy Metadata Syntax Caveat

| Legacy Form | Preferred Snort 3 Form |
|---|---|
| `metadata: service http;` | `service:http;` |
| `metadata:key value; metadata:key2 value2;` | `metadata:key value,key2 value2;` |

Use metadata for descriptive context, not as a substitute for explicit semantic keywords such as `service:`.

## Options to Always Review Manually

These are not always invalid, but should be reviewed in every migration:

1. `replace` usage when rule action is not explicitly rewrite-compatible in deployment policy.
2. `flowbits` dependencies across separate SIDs (ordering and state assumptions).
3. Complex `pcre` expressions with multiple legacy buffer flags.
4. Destination negation patterns converted to `any` that may broaden scope significantly.

## Quick Conversion Checklist

1. Remove `uricontent` and migrate to `http_uri; content:`.
2. Convert Snort 2 HTTP modifiers to sticky buffers.
3. Convert standalone content modifiers to inline style.
4. Convert `drop` and `sdrop` to `block`.
5. Convert legacy service metadata to explicit `service:`.
6. Replace incompatible destination `!$VARIABLE` with `any`.
7. Strip Snort 2 HTTP PCRE buffer flags after adding sticky buffer context.
8. Review `dsize` and `flags` semantics for stream-safe intent.
