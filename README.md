For Windows platform network encryption, please refer to this cool stuff [tcpcrypt](http://tcpcrypt.org/).

> *NEED A WIRESHARK GIF PREVIEW HERE.*

## Introduction

This is a project trying to encrypt **Payload of L4** with *Symmetrical Encryption* based on *Linux Netfilter* subsystem.

Just imagine that the intermediate routers could not know what you are actually transmitting, on which protol with what content.

## Method

> *NEED UPDATE IN THE FUTURE*

## Runtime options

The kernel module keeps the current hardcoded peer address and key, but can
limit TCP payload encryption/decryption to one TCP service port:

```sh
sudo insmod nl4_bypass.ko encrypt_port=8081
```

`encrypt_port=0` is the default and processes all TCP ports for the configured
peer. `encrypt_port=N` only applies to TCP traffic where the source or
destination port equals `N`; non-TCP handling is unchanged. For remote SSH
management, use a demo service port such as `8081` or `8082` so SSH port `22`
is bypassed.

## TODO

+ [x] ~~Asynchronous encyrption adding *waitting completion*~~
+ [x] ~~Encryption verified, *skb_put* verified~~
+ [x] ~~IPv4 checksum re-calculate~~
+ [x] ~~Decryption suite~~
+ [x] Mod&Fix to suit 6.6.87.2 kernel
+ [x] update encryption implementation
+ [ ] use **genl** for dynamic SYM_KEY from userspace
+ [ ] use **genl** for dynamic ALLOWED_ADDRESS_LIST from userspace
+ [ ] Exchange Allowed IP List with Customed **ICMP** Message
