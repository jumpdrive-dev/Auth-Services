# Jumpdrive-Auth

Rust crate which provides some common services for implementing authentication in applications.

## Usage

I currently have no intentions to publish this to crates.io, so for now if you want to use this you can add as a git
dependency using:

```toml
jumpdrive-auth = { git = "https://github.com/Jumpdrive-dev/Auth-Services", tag = "2.3.1" }
```

## Features

Currently, implements the following services and planned services:

- [x] Password hash service
- [x] JWT service
- [x] 2FA service
- [ ] Passkey service
