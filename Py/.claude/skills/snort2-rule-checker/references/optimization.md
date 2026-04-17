# Snort 2 Optimization & Tuning Reference

## 1. Rule Performance Optimization

### Fast Pattern Selection

Snort uses a multi-pattern search engine (MPSE) to pre-filter packets. Only the **fast pattern** content is matched against all packets; all other options only run when the fast pattern matches.

**Rules:**
- Snort automatically selects the longest `content` as the fast pattern
- Use `fast_pattern` keyword to override this selection manually
- Use `fast_pattern:only` to tell Snort ONLY the fast pattern should be used for matching (no other content checks needed to confirm)
- Use `fast_pattern:offset,length` to select a specific substring as the fast pattern

**Fast Pattern Constraints:**
- Only **one** `fast_pattern` per rule
- Cannot be used on negated content (`content:!"..."`)
- `fast_pattern:only` cannot have `depth`, `offset`, `distance`, or `within` modifiers

**Best practice:** Put the most unique, longest content string first and mark it as `fast_pattern`.

```
# Optimized: unique string as fast pattern
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"SQL injection attempt";
  flow:to_server,established;
  content:"UNION SELECT"; fast_pattern; nocase;
  pcre:"/UNION\s+SELECT\s+.+FROM/i";
  sid:10001; rev:1;
)
```

### Content Ordering

1. Put the **most unique** content string first (best pre-filter)
2. Put **least likely** content second (early exit on non-match)
3. Use `depth` and `offset` to constrain searches when you know position
4. Use `distance` and `within` for relative positioning after first match

### Avoid Heavy Detection on Every Packet

- Use `flow:established` for application-layer checks (skips SYN/SYN-ACK)
- Use `flow:to_server` or `flow:to_client` to halve the packet space
- Use `flow:only_stream` for checks that need reassembled data
- Use `flow:no_stream` with `dsize` (dsize fails on rebuilt packets)

---

## 2. Variable Tuning

### Critical Variables in snort.conf

| Variable | Default | Recommendation |
|----------|---------|----------------|
| `$HOME_NET` | `any` | **Set to your protected network(s)** |
| `$EXTERNAL_NET` | `any` | Set to `!$HOME_NET` (or `any` if detecting internal threats) |
| `$HTTP_SERVERS` | `$HOME_NET` | Narrow to actual web server IPs |
| `$SQL_SERVERS` | `$HOME_NET` | Narrow to actual DB server IPs |
| `$SMTP_SERVERS` | `$HOME_NET` | Narrow to actual mail server IPs |
| `$DNS_SERVERS` | `$HOME_NET` | Narrow to actual DNS server IPs |
| `$HTTP_PORTS` | `80` | Add `8080`, `8443`, `8180`, etc. as needed |
| `$SHELLCODE_PORTS` | `!80` | Ports where shellcode detection runs |

**Key principle:** `$HOME_NET` = assets you intend to protect with THIS sensor, not the entire network. Each sensor should have a `$HOME_NET` scoped to what it monitors.

**Performance impact:** Rules using `$HTTP_SERVERS` only fire when traffic is destined for those IPs. Narrowing server variables from `$HOME_NET` to specific IPs eliminates unnecessary rule evaluation.

---

## 3. Rule Selection

### Only Enable Relevant Rules

Before enabling a ruleset, ask:
- Does our network run the targeted service/protocol?
- Does the targeted OS match our environment?
- Does the targeted software version exist in our environment?

Example: No need to enable Windows-specific exploit rules if your server fleet is Linux-only.

### Rule Category Strategy

| Category | When to enable |
|----------|---------------|
| `exploit` | Always — critical vulnerabilities |
| `web-application-attack` | If running web servers |
| `sql` | If running SQL servers |
| `smtp` | If running mail servers |
| `dns` | If running DNS servers |
| `policy` | Review carefully — many false positives |
| `p2p` | Only if P2P policy enforcement needed |
| `chat` | Only if IM policy enforcement needed |

---

## 4. Event Filtering (threshold.conf)

Event filtering reduces alert volume without disabling rules entirely.

### Syntax

```
event_filter gen_id G, sig_id S, type <limit|threshold|both>, track <by_src|by_dst>, count N, seconds T;
```

### Filter Types

| Type | Behavior |
|------|---------|
| `limit` | Alert at most N times per T seconds per tracked entity |
| `threshold` | Alert every Nth time per T seconds per tracked entity |
| `both` | Alert once per T seconds after Nth occurrence per tracked entity |

### Examples

```
# Alert at most once per minute per source for SID 1234
event_filter gen_id 1, sig_id 1234, type limit, track by_src, count 1, seconds 60;

# Alert every 10th occurrence per source
event_filter gen_id 1, sig_id 5678, type threshold, track by_src, count 10, seconds 60;

# Alert once per hour after 5 occurrences per destination
event_filter gen_id 1, sig_id 9999, type both, track by_dst, count 5, seconds 3600;

# Global filter for all sigs of a gen_id
event_filter gen_id 1, sig_id 0, type limit, track by_src, count 5, seconds 60;
```

**Remember:** Must `include threshold.conf` in snort.conf.

### In-Rule Rate Threshold (`detection_filter`)

Instead of threshold.conf, put the filter directly in the rule:

```
detection_filter:track <by_src|by_dst>, count C, seconds S;
```

This is more precise — it applies only to this specific rule and is evaluated as part of detection (not post-detection).

```
alert tcp any any -> $HTTP_SERVERS 80 (
  msg:"HTTP flood";
  flow:to_server,established;
  content:"GET"; http_method;
  detection_filter:track by_src, count 100, seconds 5;
  sid:20001; rev:1;
)
```

---

## 5. Suppression

Suppression completely silences specific alerts, optionally filtered by IP.

### Syntax

```
# Completely suppress
suppress gen_id G, sig_id S;

# Suppress from specific source IP
suppress gen_id G, sig_id S, track by_src, ip X.X.X.X;

# Suppress to specific destination CIDR
suppress gen_id G, sig_id S, track by_dst, ip 10.0.0.0/8;
```

### When to suppress vs. tune

| Situation | Action |
|-----------|--------|
| Rule fires on known-good tool/scanner you control | Suppress by source IP |
| Rule fires on legitimate server behavior | Suppress by dest IP or tune rule |
| Rule fires on all traffic from a trusted network | Suppress by source CIDR |
| Rule is just too noisy globally | Event filter (limit/threshold) |
| Rule is completely irrelevant to your environment | Disable the rule |

---

## 6. Preprocessor Tuning

### frag3 (IP Defragmentation)

```
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy <windows|bsd|linux|first|last> \
  bind_to <IP/CIDR> \
  timeout 180 \
  min_frag_len 0
```

**Default policy is `first`** (HP-UX / classic BSD style). Change to match your actual OS:
- Windows: `windows`
- Linux: `linux`  
- BSD/macOS: `bsd`

Wrong policy = missed detections and false positives on fragmented traffic.

### stream5 (TCP Reassembly)

```
preprocessor stream5_global: max_tcp 262144, track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy <windows|linux|bsd|...> \
  bind_to <IP/CIDR> \
  ports client <port list> \
  ports server <port list>
```

Target-based reassembly: bind different OS policies to different IP ranges to accurately model how each OS processes TCP streams.

### http_inspect

```
preprocessor http_inspect: global \
  iis_unicode_map unicode.map 1252 \
  detect_anomalous_servers \
  proxy_alert

preprocessor http_inspect_server: server <IP> \
  profile <all|iis|apache|iis4_0|iis5_0> \
  ports { 80 8080 8180 } \
  server_flow_depth 0 \
  oversize_dir_length 500
```

**Server profiles:**
- `all` — Generic; works for most; use when platform unknown
- `iis` — Microsoft IIS
- `apache` — Apache httpd
- `iis4_0`, `iis5_0` — Older IIS versions

**Key options:**
- `detect_anomalous_servers` — Alerts on HTTP over non-standard ports (use temporarily to discover rogue web servers)
- `proxy_alert` — Alerts on unexpected proxy behavior (use with `allow_proxy_use` to whitelist known proxies)
- `server_flow_depth 0` — Inspect entire response body (performance cost; default is 300 bytes)

---

## 7. Sensor Placement Strategy

### What $HOME_NET should be per sensor

| Sensor position | $HOME_NET |
|----------------|-----------|
| DMZ sensor | DMZ subnet only |
| Internal sensor | Internal network range |
| Internet-facing sensor | All internal assets behind it |

### Alert Qualification (True Positive Assessment)

When evaluating an alert, ask:
1. **Is the target vulnerable?** Check OS/software/version against rule conditions
2. **Is the traffic direction correct?** Inbound to server vs. outbound from client
3. **Is the source IP suspicious?** External vs. internal; known good vs. unknown
4. **Is this the right context?** HTTP_Inspect alert against a user browsing = probably noise; same alert against a web server = investigate

### Alert Context: Preprocessor alerts

- Preprocessor alert triggered by random browsing → likely noise (low priority)
- Same preprocessor alert directed at a server in `$HOME_NET` → investigate
- Enable `detect_anomalous_servers` temporarily to inventory web servers in environment

---

## 8. Common Optimization Anti-Patterns

| Anti-Pattern | Problem | Fix |
|-------------|---------|-----|
| `$HOME_NET any` | All rules fire on all traffic | Set `$HOME_NET` to actual protected ranges |
| Server vars = `$HOME_NET` | SQL/HTTP/SMTP rules fire on all hosts | Narrow to actual server IPs |
| Enabling all rule categories | High false positive rate; CPU overhead | Enable only relevant protocol/service categories |
| PCRE without `content` pre-filter | PCRE runs on every packet | Always precede PCRE with at least one `content` |
| Using `flags:A+` instead of `flow:established` | Less efficient than stream5 integration | Replace with `flow:to_server,established` |
| Suppressing entire gen_id 1 globally | Silences all detection | Use per-SID suppression with IP constraints |
| No event filtering on noisy rules | Alert fatigue; missed incidents | Apply `detection_filter` or `event_filter` to high-volume rules |
| Wrong frag3 policy | Fragmentation evasion / false positives | Bind correct OS policy to each IP range |
