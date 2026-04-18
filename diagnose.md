# Diagnosis (WSL2, insmod crash + TCP unreachable)

## High-likelihood kernel crash causes

1) skb_put without tailroom check (LOCAL_OUT)
- Location: nf_hookfn_out in nl4_entry.c
- Behavior: padding expands skb with skb_put(padding_len) but no skb_tailroom check.
- Impact: if tailroom is insufficient, skb_put can trigger a BUG or memory corruption.
- Typical trigger: small skbs, GSO/TSO skbs, or tight tailroom on loopback/virtual NICs.

2) Padding parser can read out-of-bounds (LOCAL_IN)
- Location: get_comp_length in nl4_utility.c
- Issues:
  - ex is char (signed), so negative values are possible.
  - no bounds check for ex > len.
- Impact: OOB reads when ex > len; negative ex may propagate to skb_trim as a negative padding_len, which increases length and can corrupt memory.
- Trigger: decrypting data that was not padded by this module, or wrong key / wrong peer.

3) Decrypting non-encrypted traffic
- Location: nf_hookfn_in in nl4_entry.c
- If the remote filter matches incorrectly, plaintext traffic is decrypted and then parsed as padding.
- This magnifies the OOB risk in get_comp_length.

## High-likelihood TCP reachability failures

1) L4 checksum / offload mismatch after encryption
- Location: nf_hookfn_out in nl4_entry.c
- Encryption happens after the TCP checksum is computed (or queued for CHECKSUM_PARTIAL).
- If CHECKSUM_PARTIAL is used, the NIC computes checksum over ciphertext, not plaintext.
- After decrypt on LOCAL_IN, the checksum field no longer matches plaintext, so TCP drops.

2) L4 length fields are not updated
- Location: nf_hookfn_out in nl4_entry.c
- TCP/UDP/ICMP headers are included in the encrypted region.
- For UDP, the length field in UDP header is not updated after padding.
- For TCP, the pseudo-header length used for checksum no longer matches the actual on-wire length.

3) Full L4 header encryption is incompatible with kernel TCP path
- Location: nf_hookfn_out / nf_hookfn_in in nl4_entry.c
- Encrypting TCP headers breaks features like GSO/TSO and connection tracking.
- Even if decryption happens before LOCAL_IN checksum verification, outbound offload still breaks.

## Correctness issue that can break filtering

1) IP2NUM endianness mismatch
- Location: IP2NUM in nl4_utility.c
- It builds a u32 directly from bytes, which is host-endian.
- iph->saddr / daddr are network-endian (__be32), so comparisons can fail.
- Result: encryption may never apply, or it may apply to the wrong IP.

## Suggested verification steps

- Add temporary logging around:
  - skb_tailroom(skb) and padding_len before skb_put.
  - padding_len returned by get_comp_length, plus len.
- Disable checksum offload on the egress interface and retest TCP.
- Restrict encryption to payload only (do not encrypt L4 headers), or recompute L4 checksum after encryption and before transmit.
- Validate that IP2NUM uses network byte order (e.g., in4_pton + htonl).
