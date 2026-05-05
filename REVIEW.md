继续基于当前工作区修改。当前文件传输正确性已经通过，但性能很差/传输卡顿。请只做 TCP 加解密 hot path 性能优化，不改变现有 seq-based Chacha20 加解密语义。

重点：
1. crypto_skcipher 和 key setup 移到 module init，只初始化一次，module exit 释放。
2. 不要在每个 TCP packet 上 crypto_alloc_skcipher()/setkey()/skcipher_request_alloc()/free。
3. 为 TCP crypto 增加 per-CPU context，预分配 skcipher_request、completion、sg、iv、scratch buffer。
4. 用 per-CPU scratch buffer 替代 nl4_tcp_crypto_cipher() 里的每包 kmalloc(data_len + skip)/kfree。
5. 保留当前逻辑：
   - tcp_seq = ntohl(tcph->seq)
   - block_index = tcp_seq / CHACHA_BLOCK_SIZE
   - skip = tcp_seq % CHACHA_BLOCK_SIZE
   - IV counter = block_index
   - nonce = 当前五元组 hash
   - payload 长度、TCP seq/ack、IP total length 不变
6. nl4_debug=0 时不要 per-packet printk；错误日志用 rate-limit。
7. make clean && make，并运行 curl/cmp 小文件和大文件测试，给出 before/after 性能对比。

非目标：
- 不做 AEAD/MAC
- 不做 key exchange
- 不支持 GSO
- 不改变 packet 格式