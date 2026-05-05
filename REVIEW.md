当前最新代码仍然在 nl4_prepare_skb() 中对 skb_is_gso(skb) 直接 return -EOPNOTSUPP，导致 outbound TCP 分支 NF_DROP。此前 nl4_perf 已证明 OUT gso>0 且出现 ret=-95 drop，这会造成 TCP 重传和 curl 卡顿。

请修复 GSO 处理，不要继续优化 crypto。

要求：
1. nl4_prepare_skb() 不要对 skb_is_gso(skb) 直接失败。
2. 对 TCP GSO skb 增加单独 fast path：
   - 只在 skb->ip_summed == CHECKSUM_PARTIAL 时启用。
   - 确保 TCP payload 可写。
   - 重新解析 iph/tcph/payload。
   - 对整个 GSO payload 调用现有 seq-based nl4_tcp_crypto_cipher() 原地 XOR。
   - 不调用 update_l4_checksum()。
   - 不重算 TCP checksum。
   - 保留 skb->ip_summed、csum_start、csum_offset、skb_shinfo(skb)->gso_*。
   - IP header 未变，不重算 IP checksum。
   - 返回 NF_ACCEPT。
3. 非 GSO skb 继续走当前 full checksum 路径。
4. 增加统计：
   - gso_seen
   - gso_encrypt_ok
   - gso_bad_csum_mode
   - gso_prepare_fail
   - gso_drop
5. nl4_perf=1 时 module exit 输出统计。
6. 验收：curl 大文件时不再出现 ret=-95 drop，gso_drop=0，文件 cmp 通过。