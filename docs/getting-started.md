# Using crowsi-pa-key-agent

Manage policy-administrator signing keys and expose only their approved public state.

## Before you start

The operator chooses private state and custody configuration. Private key material must not enter public projections.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Initialize explicitly selected key custody.
- Perform bounded signing through the declared key interface.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
