# Snort 3 Rule Options - Complete Reference

## Rule Header Forms

Traditional:

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

Service rule:

```
action service (options;)
```

File rule:

```
action file (options;)
```

File identification rule:

```
file_id (options;)
```

## Actions

| Action | Purpose | Notes |
|------|---------|------|
| `alert` | Generate event/alert | Standard IDS behavior |
| `log` | Log packet/event data | No alert-only mode |
| `pass` | Mark packet as passed | Skip further IPS checks for matched rule path |
| `drop` | Drop current packet | Inline mode |
| `block` | Block current and subsequent packets in flow | Inline flow control |
| `reject` | Terminate session with TCP reset or ICMP unreachable | Active response |
| `rewrite` | Rewrite packet payload with `replace` | Requires `replace` |
| `react` | Respond to client and terminate session | Active response |

Note: `allow` appears in binder/IPS policy control context, not as a standard text rule action token in this guide.

## Protocols and Service Headers

Traditional protocol tokens:
- `ip`, `icmp`, `tcp`, `udp`

Service-in-header mode:
- Use service name in header position: `alert http (...)`, `alert dns (...)`
- Service must match service detected by Snort for header-service rules

## IP and Port Syntax

### IP formats
- `any`
- single IP: `192.168.1.5`
- CIDR: `192.168.1.0/24`
- variable: `$HOME_NET`
- list: `[192.168.1.0/24,10.1.1.0/24]`
- negation: `!192.168.1.0/24` or `![192.168.1.0/24,10.1.1.0/24]`

### Port formats
- `any`
- single: `80`
- range: `1:1024`, `:6000`, `500:`
- variable: `$HTTP_PORTS`
- list: `[80,443,8080,$HTTP_PORTS]`
- negation: `!80`, `![80,443]`

### Direction operators
- `->` one-way
- `<>` bidirectional

---

## General Rule Options

| Keyword | Format | Notes |
|------|--------|------|
| `msg` | `msg:"text";` | Message for event output |
| `reference` | `reference:scheme,id;` | Typical schemes: `cve`, `url` |
| `gid` | `gid:number;` | Optional, defaults to 1 for standard text rules |
| `sid` | `sid:number;` | Unique signature ID; local rules should start at 1000000 |
| `rev` | `rev:number;` | Rule revision, defaults to 1 if omitted |
| `classtype` | `classtype:name;` | One per rule |
| `priority` | `priority:number;` | Overrides classtype priority |
| `metadata` | `metadata:key value[,key value]...;` | Free-form key-value |
| `service` | `service:svc[,svc]...;` | Service scoping option; migrated from Snort 2 metadata usage |
| `rem` | `rem:"comment";` | In-rule comment metadata |
| `file_meta` | `file_meta:type T,id N[,category "..."][,group "..."][,version "..."];` | For `file_id` rules |

Important migration note:
- Snort 2 service declarations in `metadata` are replaced by the explicit `service` keyword in Snort 3.

---

## Payload Detection Options

### Core content matching

| Keyword | Format | Notes |
|------|--------|------|
| `content` | `content:[!]"pattern"[,modifier ...];` | ASCII, hex (`|41 42|`), or mixed |
| `fast_pattern` | inline content modifier | Explicit fast-pattern selector |
| `fast_pattern_offset` | inline content modifier | Skip leading bytes of content for fast-pattern |
| `fast_pattern_length` | inline content modifier | Use only selected content span for fast-pattern |
| `nocase` | inline content modifier | Case-insensitive compare |
| `width` | inline content modifier | `width 8`, `width 16`, `width 32` |
| `endian` | inline content modifier | `endian big` or `endian little` |
| `offset` | inline content modifier | Start from absolute/variable offset |
| `depth` | inline content modifier | Limit search distance from start/offset |
| `distance` | inline content modifier | Relative start from previous match |
| `within` | inline content modifier | Relative window size from previous match |

Ordering and validity notes:
- Content modifiers are inline and comma-separated in Snort 3.
- `offset/depth` pair together; `distance/within` pair together.
- Do not mix `offset` with `within` on a single content.

### Sticky buffers and payload context

| Keyword | Type | Notes |
|------|------|------|
| `pkt_data` | sticky buffer | Normalized packet data (default context) |
| `raw_data` | sticky buffer | Raw packet bytes; replaces Snort 2 `rawbytes` |
| `file_data` | sticky buffer | Normalized/decoded file payload context |
| `js_data` | sticky buffer | Normalized JavaScript buffer (version dependent) |
| `vba_data` | sticky buffer | VBA macro buffer (requires decompression config) |
| `base64_decode` | decoder option | Decode selected base64 bytes |
| `base64_data` | sticky buffer | Decoded base64 buffer (after `base64_decode`) |

### HTTP sticky buffers

| Keyword | Description |
|------|-------------|
| `http_uri` | normalized URI, supports selectors `scheme`, `host`, `port`, `path`, `query`, `fragment` |
| `http_raw_uri` | raw URI, same selectors |
| `http_header` | normalized headers, supports `:field header_name` and optional `,request` |
| `http_raw_header` | raw headers, supports field and optional request |
| `http_cookie` | normalized cookie values, optional request |
| `http_raw_cookie` | raw cookie values, optional request |
| `http_client_body` | normalized request body |
| `http_raw_body` | raw request/response body (with dechunk/decompress behavior) |
| `http_param` | selected parameter value, `http_param:"name"[,nocase];` |
| `http_method` | method buffer (`GET`, `POST`, etc.) |
| `http_version` | HTTP version buffer, optional request |
| `http_stat_code` | response status code |
| `http_stat_msg` | response status text |
| `http_raw_request` | raw request line |
| `http_raw_status` | raw status line |
| `http_trailer` | normalized trailers, optional field/request |
| `http_raw_trailer` | raw trailers, optional field/request |
| `http_true_ip` | original client IP from proxy-forward headers |

### HTTP non-sticky test options

| Keyword | Format |
|------|--------|
| `http_version_match` | `http_version_match:"vlist"[,request];` |
| `http_max_header_line` | single/range compare with optional request |
| `http_max_trailer_line` | single/range compare with optional request |
| `http_num_headers` | single/range compare with optional request |
| `http_num_trailers` | single/range compare |
| `http_num_cookies` | single/range compare with optional request |
| `http_header_test` | `http_header_test:field name[,numeric true|false][,check range][,absent][,request];` |
| `http_trailer_test` | `http_trailer_test:field name[,numeric true|false][,check range][,absent];` |

Migration note:
- Snort 2 HTTP content modifiers changed to sticky buffers in Snort 3.

### Length and existence checks

| Keyword | Format | Notes |
|------|--------|------|
| `bufferlen` | `bufferlen:[op]N[,relative];` or range | Works against current sticky buffer |
| `isdataat` | `isdataat:[!]N[,relative];` | Verify data exists at position |
| `dsize` | `dsize:[op]N;` or range | Payload size check |

### Regular expressions

| Keyword | Format | Notes |
|------|--------|------|
| `pcre` | `pcre:[!]"/expr/flags";` | Sticky-buffer aware in Snort 3 |
| `regex` | `regex:"/expr/flags"[,fast_pattern][,nocase];` | Hyperscan-backed option |

### Byte/field operations

| Keyword | Purpose |
|------|---------|
| `byte_extract` | Extract bytes to variable |
| `byte_test` | Compare bytes against value/operator |
| `byte_math` | Perform math on extracted values |
| `byte_jump` | Advance cursor based on extracted value |

### BER and protocol helpers

| Keyword | Purpose |
|------|---------|
| `ber_data` | Move cursor to BER value of given tag/type |
| `ber_skip` | Skip BER element, optional mode |
| `ssl_state` | Match SSL/TLS session state |
| `ssl_version` | Match SSL/TLS version |

### DCE/SIP and protocol-specific options

| Group | Options |
|------|---------|
| DCE | `dce_iface`, `dce_opnum`, `dce_stub_data` |
| SIP | `sip_method`, `sip_header`, `sip_body`, `sip_stat_code` |
| Sensitive data | `sd_pattern` |
| Legacy protocol exploit check | `cvs` |
| Hash checks | `md5`, `sha256`, `sha512` |
| GTP | `gtp_info`, `gtp_type`, `gtp_version` |
| DNP3 | `dnp3_func`, `dnp3_ind`, `dnp3_obj`, `dnp3_data` |
| CIP/ENIP | `cip_attribute`, `cip_class`, `cip_conn_path_class`, `cip_instance`, `cip_req`, `cip_rsp`, `cip_service`, `cip_status`, `enip_command`, `enip_req`, `enip_rsp` |
| IEC104 | `iec104_apci_type`, `iec104_asdu_func` |
| MMS | `mms_func`, `mms_data` |
| Modbus | `modbus_data`, `modbus_func`, `modbus_unit` |
| S7CommPlus | `s7commplus_content`, `s7commplus_func`, `s7commplus_opcode` |

---

## Non-Payload Detection Options

| Keyword | Purpose |
|------|---------|
| `fragoffset` | IP fragment offset checks |
| `ttl` | IP TTL checks |
| `tos` | IP ToS checks |
| `id` | IP ID checks |
| `ipopts` | IP option presence checks |
| `fragbits` | Fragment bits checks |
| `ip_proto` | IP protocol field checks |
| `flags` | TCP flag checks |
| `flow` | Direction/state/stream/frag flow checks |
| `flowbits` | Session-state flags across TCP/UDP flow |
| `file_type` | File type/version constrained matching |
| `seq` | TCP sequence number checks |
| `ack` | TCP ack number checks |
| `window` | TCP window checks |
| `itype` | ICMP type checks |
| `icode` | ICMP code checks |
| `icmp_id` | ICMP ID checks |
| `icmp_seq` | ICMP sequence checks |
| `rpc` | SUNRPC call parameter checks |
| `stream_reassemble` | Enable/disable stream reassembly per matching traffic |
| `stream_size` | Stream byte-count checks |

### flow syntax

```
flow:[{established|not_established|stateless}][,{to_client|to_server|from_client|from_server}][,{no_stream|only_stream}][,{no_frag|only_frag}];
```

### flowbits syntax

```
flowbits:{set|unset},bit[&bit]...;
flowbits:{isset|isnotset},bit[|bit]...;
flowbits:{isset|isnotset},bit[&bit]...;
flowbits:noalert;
```

### Additional flowbits notes
- `set` and `unset` of multiple bits use `&`
- `isset` and `isnotset` support `|` (any) or `&` (all)
- bit names should be alphanumeric and can include `.`, `-`, `_`

---

## Post-Detection Options

| Keyword | Format | Notes |
|------|--------|------|
| `detection_filter` | `detection_filter:track by_src|by_dst,count C,seconds S;` | One per rule |
| `replace` | `replace:"string";` | Pair with `rewrite` action |
| `tag` | `tag:session|host_src|host_dst,packets N|seconds N|bytes N;` | Log additional context after event |

---

## Metadata Policy and Rule-Group Context

Snort 3 metadata can carry policy and grouping context used by operational workflows.

Common pattern:

```
metadata:policy max-detect-ips drop,policy security-ips drop;
```

Guidance:
- Keep metadata policy declarations consistent with intended deployment mode.
- Validate action intent (`alert`/`drop`/`block`) against active IPS policy profile.
- Avoid stale Snort 2 metadata conventions for service declarations; use `service:` keyword.

---

## New Rule Types and Related Options

### Service rules
- Header: `action service`
- Service must match app detection
- Usually do not require explicit `service:` option

### File rules
- Header: `action file`
- Use `file_data;` for payload checks
- Avoid service/flow over-constraining unless needed by design

### File identification rules
- Header: `file_id`
- Must use `file_meta` plus `file_data` content logic
- Depends on file-id infrastructure in config (`file_id`, `file_policy`)

---

## Snort 2 to Snort 3 Migration Checklist

- Replace `rawbytes` with `raw_data;`
- Replace `urilen` with `http_uri;` plus `bufferlen`
- Replace `uricontent` conventions with explicit `http_uri;` plus `content`
- Replace HTTP content modifiers with sticky buffers (`http_uri;`, `http_header;`, etc.)
- Move service declarations from `metadata` to `service:`
- Revisit `fast_pattern:only` assumptions (Snort 3 fast-pattern handling changed)
- Use inline content modifier style (`content:"x",nocase,fast_pattern;`)
- Verify PCRE does not rely on Snort 2 HTTP PCRE buffer flags
