# Jumpdrive-Auth
Rust crate which provides some common services for implementing authentication in applications.

## Usage

I currently have no intentions to publish this to crates.io, so for now if you want to use this you can add it as a submodule using:

```shell
git submodule add https://github.com/rster2002/Jumpdrive-Auth.git auth
```

You can replace 'auth' with anything you like the auth crate in your application to be called.

## Features

Currently implements the following services and planned services:

- [x] Password hash service
- [x] JWT service
- [ ] 2FA service
- [ ] Passkey service
