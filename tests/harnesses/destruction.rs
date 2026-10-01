//! Destructive flows stay isolated from ordinary authorization scenarios.

#[path = "../support/mod.rs"]
mod support;

#[path = "../authorized_destruction.rs"]
mod authorized_destruction;
#[path = "../authorized_destruction_fail_closed.rs"]
mod authorized_destruction_fail_closed;
#[path = "../authorized_destruction_locked_finish.rs"]
mod authorized_destruction_locked_finish;
#[path = "../authorized_destruction_rejection.rs"]
mod authorized_destruction_rejection;
#[path = "../authorized_destruction_replay.rs"]
mod authorized_destruction_replay;
#[path = "../authorized_destruction_webauthn.rs"]
mod authorized_destruction_webauthn;
#[path = "../trust_domain_destruction.rs"]
mod trust_domain_destruction;
