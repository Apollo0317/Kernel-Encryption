For Windows platform network encryption, please refer to this cool stuff [tcpcrypt](http://tcpcrypt.org/).

> *NEED A WIRESHARK GIF PREVIEW HERE.*

## Introduction

This is a project trying to encrypt **Payload of L4** with *Symmetrical Encryption* based on *Linux Netfilter* subsystem.

Just imagine that the intermediate routers could not know what you are actually transmitting, on which protol with what content.

## Method

> *NEED UPDATE IN THE FUTURE*

## Runtime usage

Build both the kernel module and user-space control app:

```sh
make
```

Rules are configured locally in `/etc/nl4enc/rules.json`; `rule add`,
`delete`, `list`, and `flush` do not require the kernel module to be loaded.
Use `apply` to sync the saved rules to the module:

```sh
sudo app/nl4enc rule add <remote-ip> --psk <psk> --remote-service 8081 --src-ip <local-ip>
sudo app/nl4enc on
sudo app/nl4enc apply
```

`remote-service` matches traffic to a service running on the remote host,
`local-service` matches traffic to a service running locally, and `all-ports`
matches all TCP payloads between the two hosts. `--key <64hex>` is still
available as a debug/advanced alternative to `--psk`.

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
