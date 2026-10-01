//! Owner-local custody for the PA verifier used by Crowsi native boundaries.

mod authorization_document;
mod control_authorization_policy;
mod credential_authorization;
mod credential_authorization_files;
mod custody;
mod destruction;
mod destruction_authorized;
mod destruction_intent;
mod destruction_model;
mod diagnosis;
mod diagnostic_event;
mod error;
mod identity_authorization;
mod identity_nonce;
mod identity_trust;
mod initialization;
mod model;
mod operation_once_cli;
#[cfg(test)]
mod operation_once_cli_tests;
#[cfg(test)]
mod operation_once_collision_tests;
#[cfg(test)]
mod operation_once_concurrency_tests;
mod operation_once_config;
mod operation_once_config_input;
#[cfg(test)]
mod operation_once_config_input_tests;
#[cfg(test)]
mod operation_once_config_tests;
mod operation_once_config_validate;
mod operation_once_crypto;
#[cfg(test)]
mod operation_once_current_tests;
mod operation_once_digest;
mod operation_once_document;
mod operation_once_file_meta;
#[cfg(test)]
mod operation_once_file_tests;
mod operation_once_files;
mod operation_once_ledger;
mod operation_once_ledger_codec;
#[cfg(test)]
mod operation_once_ledger_crash_tests;
mod operation_once_ledger_dir;
mod operation_once_ledger_io;
mod operation_once_ledger_lock;
#[cfg(test)]
mod operation_once_ledger_quota_tests;
mod operation_once_ledger_recover;
mod operation_once_ledger_scan;
#[cfg(test)]
mod operation_once_ledger_security_tests;
#[cfg(test)]
mod operation_once_ledger_static_tests;
#[cfg(test)]
mod operation_once_ledger_test_support;
mod operation_once_ledger_watermark;
#[cfg(test)]
mod operation_once_ledger_watermark_tests;
mod operation_once_legacy;
#[cfg(test)]
mod operation_once_legacy_tests;
#[cfg(test)]
mod operation_once_output_tests;
mod operation_once_pin;
#[cfg(test)]
mod operation_once_prepared_recovery_tests;
mod operation_once_record;
#[cfg(test)]
mod operation_once_recovery_support;
#[cfg(test)]
mod operation_once_recovery_tests;
mod operation_once_runtime;
#[cfg(test)]
mod operation_once_runtime_tests;
#[cfg(test)]
mod operation_once_test_support;
#[cfg(test)]
mod operation_once_tests;
mod operation_once_verify;
mod passkey_authentication;
mod passkey_rebind;
mod passkey_recovery;
#[cfg(feature = "bootstrap-authorizer-internal")]
mod passkey_registration;
#[cfg(feature = "bootstrap-authorizer-internal")]
mod passkey_registration_proof;
mod private_json;
mod private_json_replacement;
mod state_file;
mod webauthn_assertion;
mod webauthn_assertion_verifier;
#[cfg(feature = "bootstrap-authorizer-internal")]
mod webauthn_attested;
mod webauthn_challenge;
mod webauthn_model;
mod webauthn_rsa;
mod webauthn_verifier;

pub use credential_authorization::{
    AuthorizationReceiptV1, create_credential_challenge, issue_credential_authorization,
};
pub use credential_authorization_files::CredentialAuthorizationFiles;
pub use custody::load_store as load_platform_custody_store;
pub use destruction::{destroy, destroy_trust_domain};
pub use destruction_authorized::destroy_trust_domain_authorized;
pub use destruction_intent::{
    create_destruction_challenge, destruction_intent_digest, preflight_trust_domain_destruction,
};
pub use destruction_model::{
    PaAuthorizedTrustDestructionV1, PaDestructionIntentV1, PaDestructionPreflightV1,
};
pub use diagnosis::diagnose;
pub use diagnostic_event::PasskeyRegistrationDiagnosticEventV1;
pub use error::{PaKeyError, PasskeyRegistrationProofRejection, Result};
pub use initialization::{initialize, status};
pub use model::{PaKeyDestructionV1, PaKeyDiagnosisV1, PaKeyStateV1, PaTrustDestructionV1};
pub use operation_once_cli::run as run_operation_authorize_once;
pub use passkey_authentication::{
    PasskeyAuthenticationReceiptV1, authenticate_passkey, create_passkey_authentication_challenge,
};
pub use passkey_rebind::{create_passkey_rebind_challenge, rebind_passkey};
pub use passkey_recovery::{LostPasskeyRecoveryReceiptV1, revoke_lost_passkey_registration};
#[cfg(feature = "bootstrap-authorizer-internal")]
pub use passkey_registration::{confirm_passkey_registration, stage_passkey_registration};
#[cfg(feature = "bootstrap-authorizer-internal")]
pub use webauthn_challenge::create_challenge;
pub use webauthn_model::{PasskeyChallengeV1, PasskeyCredentialV1, PasskeyStatusV1};
pub use webauthn_verifier::passkey_status;
