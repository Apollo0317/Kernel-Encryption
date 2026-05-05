当前最新 commit 已经把 TCP crypto_skcipher/setkey/request/scratch 移到 init/per-CPU，但传输速度仍没有明显提升。请继续优化 TCP hot path，不改变现有 seq-based Chacha20 语义。

现有瓶颈：
nl4_tcp_crypto_cipher() 仍然每包执行：
- spin_lock_bh()
- memcpy payload -> scratch
- crypto_skcipher_encrypt/decrypt scratch
- memcpy scratch -> payload
- 后续 full TCP checksum 重算

目标：
减少每包内存拷贝和 skcipher request 开销。

修改要求：
1. 不再把 payload 拷贝进 scratch 再拷贝回来。
2. 改为直接生成 Chacha20 keystream，并对 TCP payload 原地 XOR：
   - tcp_seq = ntohl(tcph->seq)
   - block_index = tcp_seq / CHACHA_BLOCK_SIZE
   - skip = tcp_seq % CHACHA_BLOCK_SIZE
   - nonce 仍由当前 packet direction 五元组 hash 派生
   - 对 payload[i] 使用 keystream[tcp_seq + i]
3. 优先使用 <crypto/chacha.h> 中当前内核可用的 low-level Chacha20 block API：
   - 每次生成 64-byte keystream block 到 per-CPU 64-byte buffer
   - 跳过首 block 的 skip 字节
   - XOR 到 data 原 payload
   - 不走 skcipher_request_set_crypt()/crypto_skcipher_encrypt()
4. 如果当前内核没有合适 low-level chacha API，则保留 skcipher fallback，但 common path 必须避免 payload memcpy in/out。
5. 修正 per-CPU context 使用：
   - 不要 get_cpu() 后立刻 put_cpu() 再操作 ctx
   - 要么使用 this_cpu_ptr 并保证不会并发重入
   - 要么使用明确的 per-CPU lockless方案
   - 如果仍用锁，说明原因并尽量缩小锁范围
6. 保留现有 correctness：
   - 不改变 payload 长度
   - 不改变 TCP seq/ack
   - 不改变 IP total length
   - curl/cmp 小文件和大文件测试必须通过
7. 性能验证：
   - 64MB 文件传输前后 time 对比
   - nl4_debug=0 时 dmesg 不刷屏
   - 如果速度仍无明显提升，增加简单计时/统计，分别统计 crypto、checksum、prepare_skb 的耗时占比

非目标：
- 不做 AEAD/MAC
- 不做 key exchange
- 不支持 GSO
- 不改变当前五元组 + TCP seq 派生 keystream 的设计