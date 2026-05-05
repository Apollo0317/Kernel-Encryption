请给当前 kernel module 增加性能统计，不要运行测试。

目标：
我本地 curl 大文件时一卡一卡，但目前无法让 agent 测试。请在代码里加入 nl4_perf 统计，让我本地测试后通过 dmesg 判断瓶颈。

要求：
1. 新增 module_param:
   static int nl4_perf = 0;
   module_param(nl4_perf, int, 0644);

2. 新增 in/out 两组统计：
   packets
   bytes
   hook_ns
   prepare_ns
   crypto_ns
   checksum_ns
   gso_count
   nonlinear_count
   ensure_writable_fail_count

3. nl4_perf=0 时尽量零开销，不要调用 ktime_get_ns()。

4. nl4_perf=1 时：
   - 在 nf_hookfn_in/out 中统计整个 hook 耗时
   - 分别统计 nl4_prepare_skb() 耗时
   - 分别统计 nl4_tcp_crypto_cipher() 耗时
   - 分别统计 update_l4_checksum()+ip_fast_csum() 耗时
   - payload_len > 0 的 TCP 包才计入 packets/bytes

5. 不要每包 printk。
   只在 nl4_fini() / module exit 时打印一次汇总。

6. 输出格式示例：
   [nl4-aes] PERF OUT packets=... bytes=... hook_ns=... prepare_ns=... crypto_ns=... checksum_ns=... gso=... nonlinear=... writable_fail=...
   [nl4-aes] PERF IN packets=... bytes=... hook_ns=... prepare_ns=... crypto_ns=... checksum_ns=... gso=... nonlinear=... writable_fail=...

7. 不改变现有加解密逻辑，不改变 packet 内容，不改变 correctness。