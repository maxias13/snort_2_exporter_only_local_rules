# Snort 2 to Snort 3 Migration Examples

This file provides complete before/after migrations for common Snort 2 patterns.

## Example 1: HTTP URI detection

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP admin path probe"; flow:to_server,established; content:"/admin"; http_uri; sid:2000001; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP admin path probe"; flow:to_server,established; http_uri; content:"/admin"; sid:2000001; rev:1;)
```

## Example 2: HTTP header detection

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious UA"; flow:to_server,established; content:"sqlmap"; nocase; http_header; sid:2000002; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious UA"; flow:to_server,established; http_header; content:"sqlmap",nocase; sid:2000002; rev:1;)
```

## Example 3: HTTP body detection

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP command injection in body"; flow:to_server,established; content:"cmd="; http_client_body; content:"wget"; nocase; distance:0; within:100; http_client_body; sid:2000003; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP command injection in body"; flow:to_server,established; http_client_body; content:"cmd="; content:"wget",nocase,distance 0,within 100; sid:2000003; rev:1;)
```

## Example 4: PCRE with URI buffer flag

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP traversal regex"; flow:to_server,established; pcre:"/\.\.\//Ui"; sid:2000004; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP traversal regex"; flow:to_server,established; http_uri; pcre:"/\.\.\//i"; sid:2000004; rev:1;)
```

## Example 5: Multi-content rule with inline modifiers

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP SQLi UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; fast_pattern; http_client_body; content:"SELECT"; nocase; distance:0; within:20; http_client_body; sid:2000005; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP SQLi UNION SELECT"; flow:to_server,established; http_client_body; content:"UNION",nocase,fast_pattern; content:"SELECT",nocase,distance 0,within 20; sid:2000005; rev:1;)
```

## Example 6: Negated content in URI

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP missing expected token"; flow:to_server,established; content:!"token="; http_uri; sid:2000006; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP missing expected token"; flow:to_server,established; http_uri; content:!"token="; sid:2000006; rev:1;)
```

## Example 7: flowbits set and check pair

### Snort 2 (setter)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage1 marker"; flow:to_server,established; content:"|FF|SMB"; depth:4; flowbits:set,smb.stage1; flowbits:noalert; sid:2000007; rev:1;)
```

### Snort 3 (setter)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage1 marker"; flow:to_server,established; content:"|FF|SMB",depth 4; flowbits:set,smb.stage1; flowbits:noalert; sid:2000007; rev:1;)
```

### Snort 2 (checker)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage2 payload"; flow:to_server,established; flowbits:isset,smb.stage1; content:"|90 90 90 90|"; sid:2000008; rev:1;)
```

### Snort 3 (checker)
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB stage2 payload"; flow:to_server,established; flowbits:isset,smb.stage1; content:"|90 90 90 90|"; sid:2000008; rev:1;)
```

## Example 8: drop to block action migration

### Snort 2
```snort
drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force packet"; flow:to_server,established; content:"SSH-"; sid:2000009; rev:1;)
```

### Snort 3
```snort
block tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force packet"; flow:to_server,established; content:"SSH-"; sid:2000009; rev:1;)
```

## Example 9: uricontent migration

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP login endpoint access"; flow:to_server,established; uricontent:"/login.php"; sid:2000010; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP login endpoint access"; flow:to_server,established; http_uri; content:"/login.php"; sid:2000010; rev:1;)
```

## Example 10: fast_pattern style change

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP shell upload attempt"; flow:to_server,established; content:"multipart/form-data"; fast_pattern; http_header; content:"filename=\"shell.php\""; nocase; http_client_body; sid:2000011; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP shell upload attempt"; flow:to_server,established; http_header; content:"multipart/form-data",fast_pattern; http_client_body; content:"filename=\"shell.php\"",nocase; sid:2000011; rev:1;)
```

## Example 11: Negated destination variable fix

### Snort 2
```snort
alert tcp $HOME_NET any -> !$AD_Servers 445 (msg:"Possible lateral SMB to non-AD host"; flow:to_server,established; content:"|FF|SMB"; sid:2000012; rev:1;)
```

### Snort 3
```snort
alert tcp $HOME_NET any -> any 445 (msg:"Possible lateral SMB to non-AD host"; flow:to_server,established; content:"|FF|SMB"; sid:2000012; rev:1;)
```

## Example 12: PCRE header/body/cookie flag migration set

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious auth chain"; flow:to_server,established; pcre:"/Authorization\x3a\s+Basic\s+[A-Za-z0-9+\/=]{20,}/Hi"; pcre:"/sessionid=[A-F0-9]{32}/Ci"; pcre:"/(cmd|exec)=/Pi"; sid:2000013; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-APP suspicious auth chain"; flow:to_server,established; http_header; pcre:"/Authorization\x3a\s+Basic\s+[A-Za-z0-9+\/=]{20,}/i"; http_raw_cookie; pcre:"/sessionid=[A-F0-9]{32}/i"; http_client_body; pcre:"/(cmd|exec)=/i"; sid:2000013; rev:1;)
```

## Example 13: Legacy metadata service to service keyword

### Snort 2
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Generic HTTP attack marker"; flow:to_server,established; content:"/wp-admin"; http_uri; metadata:service http; sid:2000014; rev:1;)
```

### Snort 3
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Generic HTTP attack marker"; flow:to_server,established; service:http; http_uri; content:"/wp-admin"; sid:2000014; rev:1;)
```

## Example 14: Missing semicolon fix before migration

### Snort 2 (input with syntax error)
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WebSocket upgrade probe"; flow:to_server,established; content:"Upgrade: websocket" http_header; sid:2000015; rev:1;)
```

### Snort 3 (after syntax repair and migration)
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WebSocket upgrade probe"; flow:to_server,established; http_header; content:"Upgrade: websocket"; sid:2000015; rev:1;)
```

## Notes

1. Keep one rule per SID and preserve SID/rev identity unless explicitly instructed.
2. Sort final output by SID ascending in migrated `.rules` files.
3. Place exactly one blank line between rules.
4. Keep output pure ASCII and comment-free for management system compatibility.
