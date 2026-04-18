# Netfilter-L4-Encryption Project Analysis

## 1. What This Project Does

This repository implements a Linux kernel module that encrypts and decrypts IPv4 packet contents by hooking into the Linux Netfilter stack.

- The README describes the goal as encrypting the "Payload of L3" using symmetric encryption on Linux Netfilter.
- In the actual code, the module operates on everything after the IPv4 header, which means it affects the IP payload, including transport-layer headers and application payload.
- The module only processes packets for one hard-coded peer IP address: `127.0.0.1`.
- It only hooks local traffic:
  - outbound: `NF_INET_LOCAL_OUT`
  - inbound: `NF_INET_LOCAL_IN`
- It does not process forwarded/router transit traffic.

In short, this is a prototype Linux kernel packet-mangling module that transparently encrypts outbound IPv4 payloads and decrypts inbound IPv4 payloads for a specific peer.

## 2. Main Mechanism

### 2.1 Hooking Points

The module registers two Netfilter hooks:

- inbound hook at `NF_INET_LOCAL_IN`
- outbound hook at `NF_INET_LOCAL_OUT`

This behavior is implemented in `nl4_entry.c`.

### 2.2 Packet Selection

The module only processes packets whose source or destination matches a single configured remote address.

- `REMOTE_IP` is defined as `127.0.0.1` in `nl4_entry.h`.
- `remoteAllowed()` compares:
  - inbound packets against `iph->saddr`
  - outbound packets against `iph->daddr`

This means the module is currently designed as a point-to-point prototype, not a general traffic encryption framework.

### 2.3 Outbound Processing Flow

For outbound packets:

1. The skb is linearized with `skb_linearize()`. If that fails, the packet is passed unchanged.
2. The module calculates the IPv4 payload length from `iph->tot_len`.
3. It pads the payload to a 16-byte boundary using an ANSI X.923-style scheme:
   - zero bytes are appended
   - the last byte stores the padding length
4. It extends the skb tail with `skb_put()`.
5. It encrypts the payload in place with `aes_crypto_cipher()`.
6. It updates `iph->tot_len`.
7. It recalculates the IPv4 header checksum with `ip_fast_csum()`.

### 2.4 Inbound Processing Flow

For inbound packets:

1. The skb is linearized with `skb_linearize()`. If that fails, the packet is passed unchanged.
2. The module decrypts the IPv4 payload in place.
3. It checks the last byte for ANSI X.923-style padding length.
4. If padding is present, it trims the skb with `skb_trim()` and reduces `iph->tot_len`.
5. It recalculates the IPv4 header checksum.

### 2.5 Cryptography Implementation

The cryptographic path is implemented in `nl4_utility.c` using the Linux kernel skcipher API.

- Cipher backend: `cbc-aes-aesni`
- Key size: 256-bit AES
- Key source: hard-coded 32-byte key filled with value `0x01`
- IV: 16 bytes, initialized to all zero
- Operation style: asynchronous skcipher request with completion wait
- Block handling: the function iterates over 16-byte blocks and encrypts/decrypts them in place

This is a kernel-space crypto prototype, not a production key-management design.

## 3. Software Platform Requirements

### 3.1 Operating System

The project is Linux-only.

Reasons:

- it is a Linux kernel module
- it depends on Linux Netfilter IPv4 hooks
- it uses Linux kernel crypto APIs
- the Makefile builds against `/lib/modules/$(uname -r)/build`

The README also notes Linux Netfilter explicitly and points Windows users elsewhere.

### 3.2 Kernel Requirements

The code is intended for Linux kernels in the 4.14+ range or newer.

Reasons:

- the README TODO marks "Mod&Fix to suit 4.14+ kernel" as completed
- the code uses `nf_register_net_hook()`, which matches modern kernel Netfilter registration style

### 3.3 Build Requirements

To build successfully, the system needs:

- a Linux kernel build tree or matching kernel headers installed at `/lib/modules/<kernel-version>/build`
- kernel module build tools such as `make` and a working compiler toolchain
- permission to build kernel modules on the host

### 3.4 Runtime Requirements

To run the module, the system needs:

- root privileges to insert and remove the kernel module
- IPv4 networking
- Netfilter support enabled in the kernel
- Linux kernel crypto skcipher support
- availability of the `cbc-aes-aesni` crypto implementation in the running kernel

### 3.5 Userspace Support

There is no userspace control tool in this repository.

- The Makefile explicitly says: `ERROR: No Userspace Program Found.`
- The README TODO lists future plans for dynamic key/address configuration via Generic Netlink (`genl`), but that is not implemented.

## 4. Hardware Requirements

The code strongly suggests x86/x86_64 hardware with AES-NI support.

Reasons:

- it requests the cipher implementation by the specific name `cbc-aes-aesni`
- that is an AES-NI-backed implementation rather than a generic AES provider name

Practical hardware assumptions:

- x86 or x86_64 CPU
- CPU AES-NI support
- a kernel configuration that exposes the AES-NI crypto implementation

If AES-NI support is unavailable, this implementation may fail at runtime when allocating the skcipher handle.

## 5. Current Build Validation

In the current environment, `make` did not complete successfully because the kernel build directory is missing:

`/lib/modules/6.6.87.2-microsoft-standard-WSL2/build: No such file or directory`

This confirms that the project expects a Linux environment with matching kernel headers installed for the running kernel.

## 6. Important Design Characteristics and Limitations

### 6.1 Scope Limitations

- Only IPv4 is handled.
- Only local inbound/outbound traffic is handled.
- Only one exact peer IP is supported.
- There is no dynamic policy management.
- There is no userspace key distribution.

### 6.2 Security Limitations

This repository should be treated as an experimental prototype, not a secure transport system.

Reasons visible in the code:

- the AES key is hard-coded
- the IV is zero-initialized
- there is no authentication or integrity protection
- there is no replay protection
- there is no key exchange mechanism

### 6.3 Networking/Protocol Limitations

- The code recalculates the IPv4 header checksum, but it does not explicitly recompute TCP or UDP checksums after modifying encrypted content length.
- Payload length calculations use `sizeof(struct iphdr)` in some places while payload access uses `iph->ihl * 4`, so packets with IPv4 options are not handled cleanly.
- Because the code encrypts the entire IP payload, it also encrypts transport headers, not only application data.

## 7. File-Level Role Summary

- `README.md`
  - very brief project description and TODO list
- `Makefile`
  - kernel module build/install/load/unload targets
- `nl4_entry.c`
  - Netfilter hook registration and packet processing flow
- `nl4_entry.h`
  - helper routines and hard-coded remote IP definition
- `nl4_utility.c`
  - AES/skcipher utility implementation, padding parsing, IP helpers
- `nl4_utility.h`
  - crypto-related declarations and macros
- `Reference/`
  - sample/reference code used as supporting material, not part of the main module build

## 8. Overall Summary

This project is a Linux kernel module prototype for transparent IPv4 payload encryption using Netfilter hooks and the kernel skcipher API. It intercepts locally generated and locally received packets for one configured peer IP, pads the IP payload to 16-byte alignment, encrypts/decrypts it in place, and updates the IPv4 header checksum.

From a platform perspective, it requires:

- Linux
- kernel module build support and matching kernel headers
- Netfilter IPv4 support
- kernel crypto API support
- likely x86/x86_64 hardware with AES-NI
- root privileges for module loading

From an engineering perspective, it is best understood as a proof-of-concept rather than a production-ready encrypted transport mechanism.
