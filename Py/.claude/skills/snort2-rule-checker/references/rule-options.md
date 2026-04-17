# Snort 2 Rule Options — Complete Reference

## Rule Anatomy

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

### Actions
| Action | Mode | Description |
|--------|------|-------------|
| `alert` | IDS | Generate alert and log packet |
| `log` | IDS | Log packet only |
| `pass` | IDS | Ignore packet |
| `drop` | IPS | Block and log packet |
| `reject` | IPS | Block, log, and send TCP RST / ICMP unreachable |
| `sdrop` | IPS | Block silently (no log) |

### Protocols
`tcp` `udp` `icmp` `ip`

### IP Address Formats
| Format | Example |
|--------|---------|
| Any | `any` |
| Single IP | `192.168.1.1` |
| CIDR | `192.168.1.0/24` |
| List | `[192.168.1.1,10.0.0.0/8]` |
| Negation | `!192.168.1.1` |
| Variable | `$HOME_NET` |

### Port Formats
| Format | Example |
|--------|---------|
| Any | `any` |
| Single | `80` |
| Range | `80:443` |
| Negation | `!80` |
| List | `[80,443,8080]` |
| Variable | `$HTTP_PORTS` |

### Direction
- `->` — one-way (src to dst)
- `<>` — bidirectional

### Rule Body
- Enclosed in `( )`
- Each option ends with `;`
- Format: `keyword:argument;` or standalone `keyword;`
- Options are AND logic

---

## General / Metadata Options

| Keyword | Format | Required | Notes |
|---------|--------|----------|-------|
| `msg` | `msg:"text";` | Yes | Alert message string |
| `sid` | `sid:N;` | **Yes** | Unique rule ID; local rules use 1000000+ |
| `rev` | `rev:N;` | Recommended | Rule revision number |
| `gid` | `gid:N;` | No | Generator ID; defaults to 1 |
| `classtype` | `classtype:name;` | No | From classification.config |
| `priority` | `priority:N;` | No | Overrides classtype default priority |
| `reference` | `reference:system,id;` | No | Systems: `cve`, `bugtraq`, `url`, `arachnids`, `mcafee` |
| `metadata` | `metadata:key value;` | No | Free-form key-value pairs |

---

## Payload Detection Options

### Content Matching

| Keyword | Format | Notes |
|---------|--------|-------|
| `content` | `content:"string";` or `content:!"string";` | Core detection; case-sensitive by default; binary via `\|hex bytes\|` |
| `nocase` | `nocase;` | Case-insensitive match; modifier for preceding `content` |
| `rawbytes` | `rawbytes;` | Skip preprocessor decoding; modifier for preceding `content` |
| `depth` | `depth:N;` | Search only first N bytes of payload; modifier for preceding `content` |
| `offset` | `offset:N;` | Start search at byte N from start; modifier for preceding `content` |
| `distance` | `distance:N;` | Start search N bytes after end of previous match (relative) |
| `within` | `within:N;` | Match must be within N bytes of previous match end (relative) |
| `fast_pattern` | `fast_pattern;` or `fast_pattern:only;` or `fast_pattern:offset,length;` | Override auto fast-pattern selection; **max once per rule**; cannot use negated content; `only` cannot have positional modifiers |

**Content modifier order rule:** `depth`/`offset` before modifiers but AFTER their `content`. Relative modifiers (`distance`/`within`) require a preceding `content` match.

**Multiple content matches = AND logic.**

### HTTP-Specific Content Modifiers

| Keyword | Applies To | Notes |
|---------|-----------|-------|
| `http_client_body` | Normalized HTTP request body | Requires `http_inspect` preprocessor |
| `http_cookie` | Normalized Cookie header | |
| `http_raw_cookie` | Unnormalized Cookie header | |
| `http_header` | Normalized HTTP headers | |
| `http_raw_header` | Unnormalized HTTP headers | |
| `http_method` | HTTP method (GET, POST, etc.) | |
| `http_uri` | Normalized request URI | Same as `uricontent` |
| `http_raw_uri` | Unnormalized request URI | |
| `http_stat_code` | HTTP response status code | e.g., `200`, `404` |
| `http_stat_msg` | HTTP response status message | e.g., `OK`, `Not Found` |
| `http_encode` | `http_encode:[uri\|header\|cookie],[encoding_type];` | Encoding types: `utf8`, `double_encode`, `non_ascii`, `base36`, `uencode`, `bare_byte` |
| `uricontent` | `uricontent:[!]"string";` | Search normalized HTTP request URI |
| `urilen` | `urilen:N;` or `urilen:<N;` or `urilen:N<>M;` | Match on URI length |

### Buffer / Cursor Control

| Keyword | Format | Notes |
|---------|--------|-------|
| `pkt_data` | `pkt_data;` | Reset cursor to raw transport payload |
| `file_data` | `file_data;` or `file_data:mime;` | Set cursor to HTTP response body or SMTP MIME body |
| `base64_decode` | `base64_decode:[bytes N][,offset N][,relative];` | Decode base64 data |
| `base64_data` | `base64_data;` | Set cursor to base64-decoded buffer |

### PCRE

| Keyword | Format | Notes |
|---------|--------|-------|
| `pcre` | `pcre:[!]"/regex/flags";` | Perl-compatible regex; see pcre.md for flags; use as last resort after content matching |

### Binary / Numeric Detection

| Keyword | Format | Notes |
|---------|--------|-------|
| `byte_test` | `byte_test:bytes,operator,value,offset[,relative][,big\|little][,string][,hex\|dec\|oct][,dce];` | Test byte field value; operators: `<`, `>`, `=`, `!`, `&`, `^` |
| `byte_jump` | `byte_jump:bytes,offset[,relative][,big\|little][,string][,hex\|dec\|oct][,align][,from_beginning][,post_offset N][,dce];` | Move cursor by value in packet |
| `byte_extract` | `byte_extract:bytes,offset,name[,relative][,multiplier N][,big\|little][,dce][,string][,hex\|dec\|oct][,align N];` | Extract bytes to named variable; **max 2 variables per rule** |
| `isdataat` | `isdataat:N[,relative];` | Verify payload has data at position N |

### Protocol-Specific Detection

| Keyword | Format | Notes |
|---------|--------|-------|
| `ftpbounce` | `ftpbounce;` | Detect FTP PORT commands with non-client IP |
| `asn1` | `asn1:option[,option];` | Options: `bitstring_overflow`, `double_overflow`, `oversize_length N`, `absolute_offset N`, `relative_offset N` |
| `cvs` | `cvs:invalid-entry;` | Detect CVE-2004-0396 CVS heap overflow |

### DCE/RPC Detection

| Keyword | Format | Notes |
|---------|--------|-------|
| `dce_iface` | `dce_iface:<uuid>[,<op><version>][,any_frag];` | Match on bound interface UUID; normalizes endianness |
| `dce_opnum` | `dce_opnum:<opnum\|range\|list>;` | Match on RPC operation number; e.g., `dce_opnum:1,3,5-10;` |
| `dce_stub_data` | `dce_stub_data;` | Set cursor to start of DCE/RPC stub data |

### SIP Detection

| Keyword | Format | Notes |
|---------|--------|-------|
| `sip_method` | `sip_method:<method-list>;` | Methods: `invite`, `cancel`, `ack`, `bye`, `register`, `options`, `refer`, `subscribe`, `update`, `join`, `info`, `message`, `notify`, `prack`; negation with `!` (only one method when negated) |
| `sip_stat_code` | `sip_stat_code:<code-list>;` | Match SIP response status codes |
| `sip_header` | `sip_header;` | Set cursor to SIP header fields |
| `sip_body` | `sip_body;` | Set cursor to SIP body (SDP content) |

### SSL/TLS Detection

| Keyword | Format | Notes |
|---------|--------|-------|
| `ssl_version` | `ssl_version:<version-list>;` | Versions: `sslv2`, `sslv3`, `tls1.0`, `tls1.1`, `tls1.2`; OR logic; multiple options for AND |
| `ssl_state` | `ssl_state:<state-list>;` | States: `client_hello`, `server_hello`, `client_keyx`, `server_keyx`, `unknown`; OR logic |

---

## Non-Payload Detection Options

### IP Header Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `ttl` | `ttl:[<\|>]N;` or `ttl:N-M;` | Check IP time-to-live field |
| `tos` | `tos:[!]N;` | Check IP TOS field |
| `id` | `id:N;` | Check IP ID field (e.g., `id:31337;`) |
| `ipopts` | `ipopts:<option>;` | Options: `rr` (record route), `eol`, `nop`, `ts` (timestamp), `sec`, `lsrr` (loose source routing), `ssrr` (strict source routing), `satid`, `any`; **only one per rule** |
| `fragbits` | `fragbits:[+\|*\|!]<bits>;` | Bits: `M` (more frags), `D` (don't frag), `R` (reserved); modifiers: `+` (these plus others), `*` (any of these), `!` (none of these) |
| `fragoffset` | `fragoffset:[<\|>]N;` | Check IP fragment offset field |
| `ip_proto` | `ip_proto:[!]<name or number>;` | Check IP protocol header field |
| `sameip` | `sameip;` | Match if source IP equals destination IP |

### TCP Header Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `flags` | `flags:[!\|*\|+]<FSRPAU12>[,<FSRPAU120>];` | Flags: `F`(FIN), `S`(SYN), `R`(RST), `P`(PSH), `A`(ACK), `U`(URG), `1`(reserved1), `2`(reserved2), `0`(no flags); modifiers: `+` (these+others), `*` (any), `!` (none); mask with `,12` |
| `seq` | `seq:N;` | Check TCP sequence number |
| `ack` | `ack:N;` | Check TCP acknowledgment number |
| `window` | `window:[!]N;` | Check TCP window size |

### UDP / ICMP Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `itype` | `itype:[<\|>]N[<>M];` | Check ICMP type value |
| `icode` | `icode:[<\|>]N[<>M];` | Check ICMP code value |
| `icmp_id` | `icmp_id:N;` | Check ICMP ID (useful for covert channel detection) |
| `icmp_seq` | `icmp_seq:N;` | Check ICMP sequence number |

### Payload Size

| Keyword | Format | Notes |
|---------|--------|-------|
| `dsize` | `dsize:[<\|>]N;` or `dsize:N<>M;` | Check packet payload size; **fails on stream-rebuilt packets** |

---

## Flow / State Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `flow` | `flow:[to_client\|to_server\|from_client\|from_server][,established\|stateless][,no_stream\|only_stream];` | Requires Stream5 preprocessor; `established` replaces `flags:A+`; `stateless` for crash-inducing packets; `no_stream` useful with `dsize` |
| `flowbits` | `flowbits:set\|unset\|toggle\|isset\|isnotset\|noalert[,state_name];` | Track state across sessions; names: alphanumeric + `.`, `-`, `_`; `noalert` suppresses alert regardless of other detections |

### flow options detail
- `to_client` / `from_server` — trigger on server responses (A→B direction, server side)
- `to_server` / `from_client` — trigger on client requests (A→B direction, client side)
- `established` — only established TCP connections (replaces `flags:A+`)
- `stateless` — trigger regardless of stream state (for malformed packets)
- `no_stream` — do not trigger on stream-rebuilt packets
- `only_stream` — only trigger on stream-rebuilt packets

---

## RPC Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `rpc` | `rpc:<app_num>,[<version>\|*],[<proc>\|*];` | Check SUNRPC CALL; wildcards with `*`; **slower than content matching** |

---

## Stream Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `stream_reassemble` | `stream_reassemble:<enable\|disable>,<server\|client\|both>[,noalert][,fastpath];` | Enable/disable TCP reassembly per session; requires Stream5 |
| `stream_size` | `stream_size:<server\|client\|both\|either>,<operator>,N;` | Match on bytes observed per TCP sequence; operators: `<`, `>`, `=`, `!=`, `<=`, `>=` |

---

## Post-Detection Options

| Keyword | Format | Notes |
|---------|--------|-------|
| `logto` | `logto:"filename";` | Log triggering packets to specified file; does not work in binary logging mode |
| `session` | `session:<printable\|binary\|all>;` | Extract TCP session data; **slow — use only for post-processing pcap** |
| `resp` | `resp:<mechanism>[,<mechanism>];` | Flexible Response (IPS); requires `--enable-flexresp3` at build time; mechanisms: `rst_snd`, `rst_rcv`, `rst_all`, `icmp_net`, `icmp_host`, `icmp_port`, `icmp_all` |
| `react` | `react:<opts>;` | Send HTML page and reset; requires `--enable-react` at build; configure page with `config react:<blockfile>` in snort.conf |
| `tag` | `tag:<type>,<count>,<metric>[,direction];` | Log additional packets after trigger; type: `session`/`host`; metric: `packets`/`seconds`; direction: `src`/`dst`; default tagged packet limit=256 |
| `replace` | `replace:"string";` | Inline mode only; replace prior matching content with string of **equal length** |
| `detection_filter` | `detection_filter:track <by_src\|by_dst>,count C,seconds S;` | In-rule rate threshold; rule fires only after C matches in S seconds per tracked IP |

---

## Common Syntax Error Checklist

| Error | Description |
|-------|-------------|
| Missing `sid` | Every rule **must** have `sid:N;` |
| Missing `;` after option | Every option must end with `;` |
| Missing closing `)` | Rule body must end with `)` |
| `depth`/`offset` before `content` | These are modifiers — they must come **after** their `content` keyword |
| `distance`/`within` without preceding `content` | Relative modifiers require a prior `content` match |
| `fast_pattern` used more than once | Only **one** `fast_pattern` per rule |
| `fast_pattern:only` with positional modifiers | `fast_pattern:only` cannot have `depth`, `offset`, `distance`, or `within` |
| Negated content with `fast_pattern` | Cannot use `fast_pattern` on a negated content (`content:!"..."`) |
| `byte_extract` more than twice | Max **2** `byte_extract` variables per rule |
| `ipopts` used more than once | Only **one** `ipopts` per rule |
| `flow` on non-TCP without `stateless` | `flow:established` only valid for TCP; use `stateless` for other protocols |
| `dsize` on reassembled streams | `dsize` always fails on stream-rebuilt packets; combine with `flow:no_stream` |
| `replace` length mismatch | `replace` string must be **same length** as matched `content` |
| `sip_method` negation with multiple methods | With `!`, only **one** method allowed |
| Wrong protocol for option | e.g., `flags` only valid for `tcp`; `itype`/`icode`/`icmp_id`/`icmp_seq` only for `icmp` |
| Missing quotes on `msg` | `msg` value must be quoted: `msg:"text";` |
| `content` hex bytes not pipe-delimited | Binary bytes must use `\|xx xx\|` format inside content string |
