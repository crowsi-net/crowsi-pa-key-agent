//! Passkey authorization scenarios share one cryptographic test executable.

#[cfg(feature = "bootstrap-authorizer-internal")]
#[path = "../passkey_registration_proof/fixture.rs"]
mod passkey_registration_fixture;
#[path = "../support/mod.rs"]
mod support;

#[path = "../challenge_lifetime.rs"]
mod challenge_lifetime;
#[path = "../current_device_status_authorization.rs"]
mod current_device_status_authorization;
#[path = "../device_identity_authorization.rs"]
mod device_identity_authorization;
#[path = "../github_observer_authorization.rs"]
mod github_observer_authorization;
#[path = "../initialization.rs"]
mod initialization;
#[path = "../instance_isolation.rs"]
mod instance_isolation;
#[path = "../lost_passkey_recovery.rs"]
mod lost_passkey_recovery;
#[path = "../passkey_authorization.rs"]
mod passkey_authorization;
#[path = "../passkey_bootstrap_boundary.rs"]
mod passkey_bootstrap_boundary;
#[path = "../passkey_diagnostic_oracle_boundary.rs"]
mod passkey_diagnostic_oracle_boundary;
#[path = "../passkey_diagnostic_projection.rs"]
mod passkey_diagnostic_projection;
#[path = "../passkey_recovery_registration.rs"]
mod passkey_recovery_registration;
#[path = "../passkey_recovery_status.rs"]
mod passkey_recovery_status;
#[path = "../passkey_registration_diagnostics.rs"]
mod passkey_registration_diagnostics;
#[path = "../passkey_registration_proof.rs"]
mod passkey_registration_proof;
#[path = "../passkey_registration_windows.rs"]
mod passkey_registration_windows;
#[path = "../passkey_stale_rebind.rs"]
mod passkey_stale_rebind;
#[path = "../passkey_stale_rebind_rejection.rs"]
mod passkey_stale_rebind_rejection;
