Update the previous diagnosis.

Environment:
- WSL2
- Local traffic confirmed to go through loopback0
- ethtool -k loopback0 shows:
  - tcp-segmentation-offload: off
  - generic-segmentation-offload: off
  - generic-receive-offload: off
  - large-receive-offload: off
  - scatter-gather: off
- Therefore do not assume the main bug is caused by GSO/GRO splitting a large skb.

Observed bug:
curl --noproxy '*' -i localhost:8082/<big_file> frequently produces corrupted / binary-looking response body for larger HTTP files, while short responses or headers often look correct.

Important current-code behavior:
nl4_crypto_cipher() currently creates a new stream cipher operation for each skb, uses a fixed key, allocates a zero IV, and starts the stream cipher from offset 0 for every packet payload.

Root cause to investigate/fix:
Even with GSO/GRO disabled, TCP is a byte stream and skb / TCP segment boundaries are not a valid cryptographic stream boundary. The implementation must not reset the stream cipher to zero IV at every skb. That only works when encryption-side and decryption-side payload chunks have exactly identical boundaries. Larger HTTP responses are split into multiple TCP payload segments, so corruption is likely once the chunk boundaries diverge.

Required fix:
For TCP, make encryption/decryption stateless and TCP-sequence-number based.

Implement a TCP-aware stream transform:
- Use TCP seq as the absolute byte offset for the first payload byte:
    offset = ntohl(tcph->seq)
- The same TCP byte sequence number must always map to the same keystream byte.
- Encryption and decryption should be XOR with the same generated keystream.
- Retransmissions must decrypt correctly.
- Do not use per-skb zero IV.
- Do not use payload length in IV/counter derivation.
- Do not change packet length, TCP seq, ACK, or HTTP Content-Length.
- Do not add padding.

Recommended concrete design:
Use AES-CTR for TCP with random-access offset support:
- Derive a deterministic base nonce from the TCP 4-tuple:
  src IP, dst IP, src port, dst port, protocol, and a direction/domain separator if needed.
- Use:
    block_index = tcp_seq / AES_BLOCK_SIZE
    skip = tcp_seq % AES_BLOCK_SIZE
- Generate enough keystream for skip + payload_len bytes.
- XOR payload with keystream starting at skip.
- This makes encryption independent of skb/segment boundaries.

Notes:
- Since traffic is local loopback and both hooks see both directions, be careful that inbound decrypt uses the same nonce derivation as outbound encrypt for the same packet direction. The tuple normalization must be consistent.
- For packets with no TCP payload, do nothing.
- UDP/ICMP can keep current packet-based behavior for now.

Also audit:
- skb writability before in-place modification.
- Re-fetch iph/tcph after any skb operation that can move data.
- TCP/IP checksum recalculation after payload modification.
- Error behavior: if crypto fails for protected TCP traffic, log and drop instead of passing corrupted/plaintext traffic onward.

Add debug logs:
- direction in/out
- seq
- payload_len
- block_index
- skip
- skb_is_gso(skb)
- skb->ip_summed
- checksum mode/action

Acceptance tests:
1. Build and load module.
2. python3 -m http.server 8082
3. Repeatedly fetch the same file:
   for i in $(seq 1 100); do
     curl --noproxy '*' -sS localhost:8082/nl4_entry.c -o /tmp/out.$i || exit 1
     cmp nl4_entry.c /tmp/out.$i || exit 1
   done
4. Test curl -i too, strip HTTP headers, and compare body bytes.
5. Confirm the fix works with loopback0 offloads already disabled.