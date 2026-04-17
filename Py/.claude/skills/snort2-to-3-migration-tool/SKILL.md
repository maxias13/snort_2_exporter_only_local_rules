# Snort 2 to Snort 3 Migration Tool

## Description

You are an expert migration assistant for converting Snort 2 rules into valid, production-ready Snort 3 rules.
When activated, you parse Snort 2 rules, apply deterministic syntax and semantic transformations, validate Snort 3 output, and produce a per-rule migration report that clearly separates auto-fixes from manual-review items.

## Triggers

Use this skill when the user:
- Says "convert to Snort 3"
- Says "migrate rule" or "migrate these rules"
- Says "update to Snort 3"
- Provides a `.rules` file and asks for migration
- Asks to modernize Snort 2 syntax for Snort 3 sticky buffers and action model

## Quick Migration Goal

Convert each Snort 2 rule to Snort 3 while preserving detection intent, reducing migration drift, and avoiding known incompatibilities.

---

## Step-by-Step Migration Workflow (Per Rule)

### Step 1: Parse and Validate the Snort 2 Rule

Check and normalize before migration:
- Header shape: `action proto src_ip src_port direction dst_ip dst_port`
- Rule body has balanced parentheses
- Every option ends with `;`
- Required fields present (`msg`, `sid`)
- Record original action, protocol, flow, content, PCRE, and metadata

If parse errors exist (for example missing `;` after `content`), fix syntax first, then migrate.

### Step 2: Identify Constructs Needing Transformation

Build a transformation plan per rule:
- Header and action changes (`drop`, `sdrop`, negated dst variables)
- Snort 2 content modifier style that must become Snort 3 sticky-buffer style
- `uricontent` and legacy HTTP buffer modifiers
- Standalone content modifiers that must become inline content modifiers
- Snort 2 PCRE HTTP buffer flags (`U`, `H`, `P`, `C`, `I`, and other legacy flags)
- Inline-mode or stream-sensitive options (`replace`, `dsize`)
- Legacy metadata patterns that should become explicit Snort 3 options (for example `service:`)

### Step 3: Apply Transformations in Required Order

Apply in this exact order to avoid cursor and buffer errors:

1. Header
2. Actions
3. Content modifiers
4. Sticky buffers
5. PCRE flags
6. Inline options and metadata normalization

Do not reorder semantic logic unless required for Snort 3 validity.

### Step 4: Validate Snort 3 Output

Validate:
- Snort 3 option style is correct (inline content modifiers)
- Sticky buffers are placed before dependent payload checks
- PCRE no longer relies on Snort 2 HTTP buffer flags
- Action set is valid for intended mode
- `sid` and `rev` present

### Step 5: Flag Manual Review Items

Mark as manual review when migration cannot be guaranteed safe:
- Ambiguous service scope (`tcp` header plus mixed app-layer options)
- Potential typo in detection literal (for example `Upgrage: websocket`)
- Logic-sensitive flowbits chains that may depend on external rule ordering
- `replace` behavior in environments not using rewrite action/policy
- Semantics that depended on Snort 2 preprocessor behavior rather than explicit buffers

---

## Transformation Rules (Exhaustive Core Mapping)

### 1) Action Mapping

| Snort 2 | Snort 3 | Notes |
|---|---|---|
| `drop` | `block` | Prefer `block` for flow-level prevention semantics |
| `sdrop` | `block` | Snort 3 does not use `sdrop` |

### 2) HTTP URI Migration

| Snort 2 Pattern | Snort 3 Pattern |
|---|---|
| `uricontent:"x";` | `http_uri; content:"x";` |
| `uricontent:!"x";` | `http_uri; content:!"x";` |

### 3) Content Modifier Model Migration

Snort 2 modifier style to Snort 3 sticky + inline style:

| Snort 2 Pattern | Snort 3 Pattern |
|---|---|
| `content:"x"; http_uri;` | `http_uri; content:"x";` |
| `content:"x"; http_header;` | `http_header; content:"x";` |
| `content:"x"; http_client_body;` | `http_client_body; content:"x";` |
| `content:"x"; http_raw_uri;` | `http_raw_uri; content:"x";` |

### 4) Inline Content Modifier Conversion

| Snort 2 Pattern | Snort 3 Pattern |
|---|---|
| `content:"x"; fast_pattern;` | `content:"x",fast_pattern;` |
| `content:"x"; nocase;` | `content:"x",nocase;` |
| `content:"x"; depth:20;` | `content:"x",depth 20;` |
| `content:"x"; offset:4;` | `content:"x",offset 4;` |
| `content:"x"; distance:0; within:40;` | `content:"x",distance 0,within 40;` |

### 5) Raw Buffer Handling

| Snort 2 | Snort 3 |
|---|---|
| `rawbytes;` | `pkt_data;` |

Note: Snort 3 also supports `raw_data;`, but this migration skill uses `pkt_data;` per required mapping.

### 6) PCRE Buffer Flag Migration

Convert buffer flags into explicit sticky buffers and remove legacy buffer flags from `pcre`:

| Snort 2 PCRE Flag | Snort 3 Sticky Buffer |
|---|---|
| `U` | `http_uri;` |
| `H` | `http_header;` |
| `P` | `http_client_body;` |
| `C` | `http_raw_cookie;` |
| `I` | `http_raw_uri;` |

Example:
- Before: `pcre:"/admin/iU";`
- After: `http_uri; pcre:"/admin/i";`

### 7) Destination Negated Variable Compatibility

| Snort 2 Header Pattern | Snort 3 Header Pattern |
|---|---|
| `... -> !$VARIABLE any (...)` | `... -> any any (...)` |

Apply specifically to destination IP negated variable forms that are not supported in target syntax/profile.

### 8) Metadata Normalization

Normalize metadata syntax and lift service hints to explicit keyword where appropriate.

| Legacy Pattern | Snort 3 Pattern |
|---|---|
| `metadata: service http;` | `service:http;` |
| `metadata:key value;` | `metadata:key value;` or `metadata:key value,key2 value2;` |

### 9) Service Hint Enrichment

When HTTP, DNS, SMTP, SIP, or file semantics are clearly present, add explicit service hints if header remains generic:
- `service:http;`
- `service:dns;`
- `service:smtp;`

Do not add speculative service hints when traffic context is unclear.

---

## Migration Report Format (Per Rule)

Use this exact report structure for each migrated SID:

```
## SID: XXXXXX
### Changes Applied
- [list of transformations performed]
### Manual Review Required
- [items needing human judgment]
### Snort 3 Rule
[output rule]
```

Rules with no manual review items must still include the section:
- `- None`

---

## Batch Migration Mode (.rules File)

When migrating full files:

1. Parse all lines and keep only rule lines for output
2. Validate and migrate each rule independently using the per-rule workflow
3. Keep a per-SID migration report entry
4. Sort migrated rules by SID ascending
5. Emit exactly one blank line between rules
6. Emit pure ASCII only
7. Emit no comments in final rules file
8. Provide a summary count:
   - total rules processed
   - fully auto-migrated
   - migrated with manual review
   - failed parse (if any)

If duplicate SIDs exist, preserve all rules but flag duplicates for manual resolution.

---

## Output Rules File Format (MANDATORY)

When writing migrated rules to a file:

1. SID ascending order
2. One blank line between each rule
3. Pure ASCII only
4. No comments (`#` lines prohibited)

Example format:

```
alert tcp ... ( ... sid:1000418; rev:1; )

alert tcp ... ( ... sid:1000419; rev:1; )

alert tcp ... ( ... sid:1000796; rev:2; )
```

---

## Common Migration Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Leaving `drop`/`sdrop` unchanged | Snort 3 action mismatch | Convert to `block` |
| Keeping `uricontent` | Parser or semantic mismatch | Use `http_uri; content:"...";` |
| Keeping Snort 2 content modifier ordering | Wrong buffer logic | Move sticky buffer before `content` |
| Leaving standalone `fast_pattern` | Invalid style | Merge inline with content |
| Leaving standalone `nocase` | Invalid style | Merge inline with content |
| Leaving PCRE buffer flags | Wrong buffer evaluation | Add sticky buffer and remove flag |
| Keeping `!$VARIABLE` in dst IP | Header incompatibility | Replace destination IP with `any` |
| Not fixing missing semicolons from source rule | Parse failure | Repair syntax before migration |
| Migrating typo literals without warning | False negative risk | Keep literal but flag manual review |
| `dsize` with stream traffic unreviewed | Missed matches | Consider `flow:no_stream` or redesign |
| Assuming `flags:A+` still best practice | Performance and intent drift | Prefer flow-based state checks |

---

## Reference Files

- [syntax-diff.md](references/syntax-diff.md) - Snort 2 vs Snort 3 syntax model differences
- [deprecated-options.md](references/deprecated-options.md) - Deprecated/removed Snort 2 options and Snort 3 replacements
- [migration-examples.md](references/migration-examples.md) - Complete before/after migration examples

---

## Practical Notes from Real Migrations

- `!$AD_Servers` in destination IP must be converted to `any`
- `uricontent` must become `http_uri; content:`
- `content:"..."; http_uri;` must become `http_uri; content:"...";`
- `fast_pattern` standalone modifier must become inline form
- Missing `;` after `content` must be repaired before conversion
- Suspicious text typos should be preserved but flagged in manual review
