# Core Algorithms & Pseudocode: PS-007
## Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

---

## Algorithm 1: RFC 4941 Privacy Extensions Address Generation

```text
Input: Subnet prefix P (e.g., 2001:db8:1::/64)
Output: Temporary IPv6 address Target_IPv6

Function GenerateTemporaryIPv6(P):
    1. Let CSPRNG be a Cryptographically Secure Pseudo-Random Number Generator
    2. Generate 64-bit random Interface Identifier:
           IID_bytes ← CSPRNG.GetBytes(8)
    3. Ensure Universal/Local (U/L) bit is set to 0 (locally administered, random):
           IID_bytes[0] ← IID_bytes[0] & 0xFD
    4. Format IID as four 16-bit hexadecimal groups:
           IID_str ← FormatHex16(IID_bytes)
    5. Construct complete IPv6 address:
           Target_IPv6 ← Concatenate(P, "::", IID_str)
    6. Return Target_IPv6
```

---

## Algorithm 2: Authenticated Ephemeral Pseudonym Assignment

```text
Input: Tenant ID T, Device ID D, Device Secret S, IPv6 Address IP, Configured TTL tau
Output: Authentication Result Object or Error

Function AuthenticateDevice(T, D, S, IP, tau):
    1. If ExpectedSecret(D) != S then:
           Raise PermissionError("Invalid Credentials")
    2. Let now ← CurrentUnixTimestamp()
    3. Let expires_at ← now + tau
    4. Generate random ephemeral session token:
           raw_token ← "tok_" + CSPRNG.GetHex(16)
           token_hash ← SHA256(raw_token)
           session_id ← "sess_" + CSPRNG.GetHex(8)
    5. Generate unique local pseudonym:
           pseudonym ← "DEV-P" + CSPRNG.GetHex(2).ToUpper()
    6. Acquire Database Mutex:
           Begin Transaction:
               UPDATE sessions SET is_active = 0 WHERE tenant_id = T AND device_id = D
               UPDATE pseudonyms SET is_active = 0 WHERE tenant_id = T AND (current_ipv6 = IP)
               INSERT INTO sessions (id, tenant_id, device_id, token_hash, pseudonym, ipv6_address, created_at, expires_at, is_active)
                   VALUES (session_id, T, D, token_hash, pseudonym, IP, now, expires_at, 1)
               INSERT INTO pseudonyms (id, tenant_id, pseudonym, session_id, current_ipv6, assigned_at, expires_at, is_active)
                   VALUES ("pseudo-" + CSPRNG.GetHex(6), T, pseudonym, session_id, IP, now, expires_at, 1)
               UPDATE devices SET status = 'AUTHENTICATED', current_ipv6 = IP, last_active_at = now
                   WHERE id = D AND tenant_id = T
           Commit Transaction
    7. Return { session_id, session_token: raw_token, pseudonym, ipv6_address: IP, expires_at, ttl: tau }
```

---

## Algorithm 3: Authenticated Address Rotation Handshake

```text
Input: Tenant ID T, Session ID S_id, Session Token raw_tok, New Address IP_new
Output: Rotation Result Object or Error

Function HandleAddressRotation(T, S_id, raw_tok, IP_new):
    1. Let now ← CurrentUnixTimestamp()
    2. Compute provided token hash:
           test_hash ← SHA256(raw_tok)
    3. Query active session:
           record ← SELECT * FROM sessions WHERE id = S_id AND tenant_id = T AND is_active = 1
    4. If record is NULL or record.expires_at <= now then:
           Raise PermissionError("Session Expired or Invalid")
    5. If ConstantTimeHMACCompare(record.token_hash, test_hash) == False then:
           Raise PermissionError("Session Token Forgery Detected")
    6. Let dev_id ← record.device_id
    7. Let old_ip ← record.ipv6_address
    8. Let persistent_pseudonym ← record.pseudonym
    9. Acquire Database Mutex:
           Begin Transaction:
               UPDATE pseudonyms SET current_ipv6 = IP_new WHERE tenant_id = T AND session_id = S_id AND is_active = 1
               UPDATE sessions SET ipv6_address = IP_new WHERE id = S_id AND tenant_id = T
               UPDATE devices SET current_ipv6 = IP_new, rotation_count = rotation_count + 1 WHERE id = dev_id AND tenant_id = T
               INSERT INTO address_rotations (tenant_id, device_id, pseudonym, old_ipv6, new_ipv6, rotated_at, status)
                   VALUES (T, dev_id, persistent_pseudonym, old_ip, IP_new, now, 'SUCCESS')
           Commit Transaction
    10. Return { status: 'SUCCESS', device_id: dev_id, pseudonym: persistent_pseudonym, old_ipv6: old_ip, new_ipv6: IP_new }
```

---

## Algorithm 4: Sliding-Window Abnormal NDP Flood Detection

```text
Input: Packet Source IP S_ip, Message Type M_type (135/136), Packet Timestamp t_pkt
Constants: Window Size W = 3.0s, Rate Threshold R_thresh = 6.0 pps, Alert Cooldown = 3.0s
State: Dictionary TimestampBuffer[S_ip], Dictionary LastAlertTime[S_ip]

Function InspectNDPPacket(S_ip, M_type, t_pkt):
    1. Let t_now ← CurrentUnixTimestamp()
    2. Let latency_ms ← (t_now - t_pkt) * 1000.0
    3. Acquire Mutex:
           cutoff ← t_now - W
           Filter TimestampBuffer[S_ip] to keep only timestamps >= cutoff
           Append t_now to TimestampBuffer[S_ip]
           current_rate ← Count(TimestampBuffer[S_ip]) / W
           is_flooding ← (current_rate > R_thresh)
           
           If is_flooding == True then:
               If (t_now - LastAlertTime[S_ip]) > Alert Cooldown then:
                   LastAlertTime[S_ip] ← t_now
                   correlated_pseudonym ← ResolveIPv6ToPseudonym(S_ip)
                   alert_id ← "ALT-NDP-" + CSPRNG.GetHex(4).ToUpper()
                   reason ← "Abnormal NDP Flooding from " + S_ip + " (" + current_rate + " pps > " + R_thresh + " pps)"
                   SaveAlertToDatabase(alert_id, "HIGH", "ABNORMAL_NDP_FLOODING", S_ip, correlated_pseudonym, reason, latency_ms)
                   Return AlertObject
    4. Return None
```

---

## Algorithm 5: Rogue Router Advertisement Whitelist Verification

```text
Input: Packet Source IP S_ip, Advertised Prefix Pref, Packet Timestamp t_pkt
Constants: TrustedRouters = {"2001:db8:1::1", "fe80::1"}, TrustedPrefix = "2001:db8:1::/64"

Function InspectRouterAdvertisement(S_ip, Pref, t_pkt):
    1. Let t_now ← CurrentUnixTimestamp()
    2. Let latency_ms ← (t_now - t_pkt) * 1000.0
    3. Normalize S_ip to standard lowercase IPv6 string
    4. is_trusted ← False
    5. For each router R in TrustedRouters:
           If S_ip == Normalize(R) then:
               is_trusted ← True
               Break
    6. If is_trusted == True and Pref != NULL and Pref != TrustedPrefix then:
           is_trusted ← False
    7. If is_trusted == False then:
           alert_id ← "ALT-RA-" + CSPRNG.GetHex(4).ToUpper()
           reason ← "Rogue Router Advertisement from unauthorized source " + S_ip
           pseudonym ← ResolveIPv6ToPseudonym(S_ip)
           SaveAlertToDatabase(alert_id, "CRITICAL", "ROGUE_ROUTER_ADVERTISEMENT", S_ip, pseudonym, reason, latency_ms)
           Return AlertObject
    8. Return None
```

---

## Algorithm 6: Empirical Evaluation Metrics Calculation

```text
Input: Ground truth state (TP, FP, TN, FN, Latencies List L)
Output: Evaluation Report

Function CalculateEvaluationMetrics(TP, FP, TN, FN, L):
    1. TotalPackets ← TP + FP + TN + FN
    2. If (TP + FN) > 0 then:
           Recall (Detection Rate) ← (TP / (TP + FN)) * 100
       Else:
           Recall ← 100.0
    3. If (TP + FP) > 0 then:
           Precision ← (TP / (TP + FP)) * 100
       Else:
           Precision ← 100.0
    4. If (FP + TN) > 0 then:
           FalsePositiveRate ← (FP / (FP + TN)) * 100
       Else:
           FalsePositiveRate ← 0.0
    5. If Length(L) > 0 then:
           AvgLatencyMs ← Sum(L) / Length(L)
       Else:
           AvgLatencyMs ← 1.0
    6. Return {
           TP, FP, TN, FN,
           DetectionRate: Round(Recall, 2),
           Precision: Round(Precision, 2),
           FalsePositiveRate: Round(FalsePositiveRate, 2),
           AvgDetectionLatencyMs: Round(AvgLatencyMs, 2),
           TotalEvaluatedPackets: TotalPackets
       }
```

