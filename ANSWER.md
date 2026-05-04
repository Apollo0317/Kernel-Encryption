
1. 这个问题的原因是什么？你是如何修改的？

原因有两层。

第一层是 TCP 是字节流，不保证 `LOCAL_OUT` 和 `LOCAL_IN` 看到的 skb/TCP 分段边界一致。原来的加解密逻辑按“每个 skb 的 payload 从 keystream offset 0 开始”处理。对于较小响应，出入方向经常刚好保持相同边界，所以看起来正常；对于较大响应，loopback/TCP 栈可能在出方向和入方向做不同的分段、合并或 GSO 处理，导致入方向同一段字节使用了错误的 keystream 位置解密，最终 curl 看到二进制 body。

第二层是 refactor 后存在不对称处理：某些出方向 TCP payload 因为 GSO/unsupported 状态没有被加密，但入方向后续可能以普通 TCP skb 形式出现并被模块解密。这样 plaintext 会被当成 ciphertext 解密，也会得到乱码。这种情况更容易出现在较大的 response body 上。

修改方式：

- TCP 加解密不再只依赖 skb 边界，而是用 `tcph->seq` 作为 stream offset，构造对应的 cipher IV 和 partial-block skip，使同一 TCP 字节流位置在出入方向使用同一段 keystream。
- 对 loopback TCP 增加“已加密 sequence range”记录。只有 `LOCAL_OUT` 实际成功加密过的 TCP sequence 范围，`LOCAL_IN` 才会解密；如果入方向 payload 没有被记录覆盖，就跳过解密，避免把未加密 plaintext 解成乱码。
- range 覆盖检查支持多个 outbound range 拼接覆盖一个 inbound coalesced skb，因为入方向可能把多个出方向段合并后交给 hook。

2. 你是如何发现的?

主要依据是 `curl.log` 里的现象和代码路径对照。

日志显示：加载模块后，HTTP status line 和 headers 经常是正常的，例如 `HTTP/1.0 200 OK`、`Content-Length: 1895` 都能被 curl 解析；但是 body 有时触发 `Warning: Binary output can mess up your terminal`。这说明 TCP 连接本身没有完全坏掉，服务端响应也不是完全不可读，问题集中在较大 body payload 的某些后续字节上。

如果 key、checksum、remote address 匹配这类基础逻辑整体错误，headers 通常也会坏；如果只是 body 偶发坏，并且小响应稳定正常，就更像是 TCP 流位置或 skb 分段边界不一致。再看当前代码，payload 加解密是在每个 skb 上独立调用 stream cipher，而 stream cipher 原本默认从 IV 对应的 keystream 起点开始。这和 TCP 字节流的语义不匹配。

随后结合较大响应才触发的特点，检查了 `nl4_prepare_skb()` 中对 `skb_is_gso(skb)` 的跳过逻辑。较大 response 更可能走 GSO 或被拆分/合并，导致出方向没有加密、入方向却解密，形成不对称。这个解释能同时覆盖“有时正常、有时 binary body”和“body 越大越容易复现”两个现象。

因此修复分成两部分：先用 TCP sequence number 解决 keystream offset 与 skb 边界绑定的问题，再用 outbound encrypted range 记录解决出入方向处理不对称的问题。

3. 为什么larger response body 在传输给curl client时可能拆成30/33(即数量不同)的tcp packet?

因为 TCP 是字节流协议，应用层的一次 `write()`、HTTP body 的大小、curl 的一次 `read()`，都不对应固定数量的 TCP packet。内核可以根据当时的发送缓冲区、MSS、拥塞控制、Nagle/PSH、GSO/TSO、loopback 设备路径、调度时机和接收端处理节奏，把同一段字节拆成不同数量的 skb/TCP segment。

在 localhost 场景里这种变化更明显。loopback 不是真实网卡链路，很多硬件相关限制不存在，内核可能先在 `LOCAL_OUT` 保留一个较大的 GSO skb，然后在后续路径再分段；也可能在 `LOCAL_IN` 或 socket 接收前把多个 segment 合并。不同 curl 请求之间，只要调度时机、发送缓冲区状态、目录 listing 内容长度、进程读写节奏有轻微差异，就可能出现 30 个或 33 个 TCP packet 这样的数量差异。

这也是为什么不能把加密逻辑绑定到“第几个 packet”或“当前 skb 内 offset”。对 TCP payload 做流式加密时，正确的对齐单位应该是 TCP byte sequence，即 `tcph->seq` 表示的字节流位置，而不是 packet 数量或 skb 边界。

4. 所以现在的方案只适用于本地的加解密测试，一旦扩展到 p22 远程主机还是存在这个问题？

不完全是，需要分开看。

`tcph->seq` 作为 stream offset 这部分不是 localhost 专用的，它是 TCP 流式加密应该采用的对齐方式。无论是本机 loopback，还是两台机器之间的真实 TCP 连接，只要中间发生分段、合并、重传、GSO/TSO/GRO 等变化，接收端都不能假设“当前 skb 从 keystream offset 0 开始”。用 TCP sequence number 对齐 keystream，理论上可以解决远程场景下“发送端和接收端看到的 packet/skb 边界不同”导致的错位问题。

但当前补上的 `nl4_tcp_range` 记录机制确实只适用于本机 loopback 测试。它依赖同一个内核同时看到 `LOCAL_OUT` 和 `LOCAL_IN`，所以能记录“本机出方向哪些 TCP sequence range 实际加密过”，再在本机入方向决定是否解密。扩展到 p22 这类远程主机时，接收端机器看不到发送端机器的 `LOCAL_OUT` 记录，因此不能依赖这个 range 表判断某段 payload 是否真的加密过。

所以远程场景下的结论是：

- 如果两端都加载模块，并且发送端所有需要保护的 TCP payload 都确实被加密，接收端按 `tcph->seq` 做 stream offset 解密，那么“较大 response 因 packet 数量不同而错位”的问题不应该继续存在。
- 如果发送端因为 `skb_is_gso()`、non-linear skb、unsupported packet 或其他条件跳过了某些 TCP payload 的加密，而接收端仍然无条件尝试解密，那么远程场景仍然会出现 plaintext 被当作 ciphertext 解密的乱码问题。
- 因此，当前代码更准确地说是“本地 loopback 测试已经增加了保护，远程测试还需要保证发送端不会静默跳过应加密 payload，或者在协议里显式标记哪些 payload 已加密”。

要把方案做成可靠的远程版本，建议不要依赖本机 range 表，而是做下面至少一种设计：

- 在发送端处理 GSO/non-linear skb：要么在线性化和分段后再加密，要么支持加密 paged skb/frags，避免 silently skip。
- 增加可识别的加密标记或轻量封装，让接收端能判断当前 payload 是否是本模块加密过的，而不是盲目解密所有匹配端口/IP 的 TCP payload。
- 对加密数据增加认证校验，例如 AEAD 或 MAC；接收端校验失败时丢包或跳过，而不是把错误解密后的乱码继续交给 TCP/application。

5. 当前 kernel module 支持什么？使用时需要注意什么？

当前模块更适合定位为“基于 Netfilter hook 的 L4 payload 加解密实验模块”，而不是可直接生产部署的完整 VPN/传输层安全方案。

当前支持的能力：

- 支持 IPv4 `LOCAL_OUT` 和 `LOCAL_IN` 路径上的 payload 处理。
- 支持 TCP payload 加解密，并使用 `tcph->seq` 作为 stream offset，使加解密不再依赖 skb/TCP packet 边界。
- 支持 UDP payload 加解密，但 UDP 是 datagram，不存在 TCP 这种跨 segment 的字节流 offset 问题。
- 支持 ICMP echo request/reply payload 加解密，非 echo 类型会跳过。
- 默认优先使用 `chacha20` skcipher，失败时回退到 `ctr(aes)`。
- 支持通过 module parameter 配置远端 IP、key、debug 日志、crypto error 处理策略等。
- 对 localhost loopback TCP 增加了“已加密 sequence range”保护，避免本机出方向跳过加密后，本机入方向又把 plaintext 当 ciphertext 解密。

当前已经改善的问题：

- 避免了 TCP 大响应因为出入方向 packet/skb 分段数量不同而导致 keystream 从错误位置开始的问题。
- 避免了本地 loopback 测试中，未加密 payload 被本机入方向误解密造成的乱码问题。
- 对 skb 可写性、IP/TCP/UDP/ICMP header 长度、fragment、checksum 重算、hook 注册失败清理等路径做了更保守的处理。

需要注意的限制：

- 本机 loopback 的 `nl4_tcp_range` 保护不能扩展到两台远程主机，因为远程接收端看不到发送端机器的 `LOCAL_OUT` 记录。
- 当前代码遇到 `skb_is_gso(skb)`、non-linear skb 或其他 unsupported skb 时仍可能跳过处理。localhost 下有 range 表兜底；远程场景下没有这个兜底。
- 远程部署时，如果发送端跳过了某段 payload 的加密，而接收端仍然按规则解密，就仍然可能出现大 response body 乱码。
- 当前没有协议级加密标记。接收端不能可靠判断某个 payload 到底是不是本模块加密过的，只能按 IP/protocol/path 规则处理。
- 当前没有认证完整性保护，例如 AEAD/MAC。密文被篡改、key/IV 不匹配、误解密时，模块不能可靠检测出来。
- 当前主要处理 IPv4，不支持 IPv6。
- 当前不是连接感知的完整 TCP proxy。它不维护完整 TCP session 状态，也不处理 SYN 初始序列号协商、重传语义、乱序缓存等更复杂情况。
- 当前 key/crypto 参数适合实验，不应直接当作安全设计。固定 key、固定或可预测 nonce、无认证，安全性都不足。

对当前版本的使用建议：

- 本地 loopback 功能测试可以继续使用当前版本，尤其适合验证 hook、payload 修改、checksum 修复、TCP stream offset 对齐这些机制。
- 远程两台主机测试时，应先关闭或规避 GSO/GRO/TSO 等 offload，降低发送端跳过 payload 加密的概率；但这只是测试规避，不是根本修复。
- 如果目标是可靠远程部署，下一步应该优先解决 GSO/non-linear skb 的处理，避免 silently skip。
- 如果目标是更接近真实安全通信，应增加明确的加密封装或标记，并加入认证校验，避免接收端盲目解密。
- 如果要长期维护，建议补充自动化测试：小/大 TCP response、UDP、ICMP、loopback、两机远程、GSO on/off、non-linear skb、错误 key、rmmod/insmod 循环。

一句话总结：当前版本对本地 loopback 大响应乱码问题做了针对性修复，并且 TCP stream offset 的核心修复对远程也有价值；但它还不能保证两台远程主机上的所有大 response 都可靠恢复，因为远程场景仍缺少“发送端一定加密成功”和“接收端能识别/认证密文”的机制。

6. 当前根据tcp seq来派生iv进而派生key stream, 但是对于