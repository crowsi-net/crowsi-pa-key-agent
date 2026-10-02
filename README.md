# crowsi-pa-key-agent

Manage policy-administrator signing keys and expose only their approved public state.

## What you can do

- Initialize explicitly selected key custody.
- Perform bounded signing through the declared key interface.

## Current scope

The operator chooses private state and custody configuration. Private key material must not enter public projections.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
