use crowsi_credential_broker::{CustodyAvailabilityError, PlatformCustodyStore};
use crowsi_pa_key_agent::{
    CredentialAuthorizationFiles, PaKeyError, diagnose, initialize, load_platform_custody_store,
    status,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    cli_parse::{Command, ParsedCommand},
    cli_passkey_registration_dispatch::bootstrap_blocked,
};

pub fn dispatch(parsed: ParsedCommand) -> Result<Value, PaKeyError> {
    require_bootstrap_available(&parsed.command)?;
    let store = load_platform_custody_store(&parsed.custody)?;
    let command = parsed.command;
    if let Command::State { operation, state } = &command {
        return dispatch_state(&store, operation, state);
    }
    let value = match command {
        Command::Destruction(command) => {
            require_available(&store)?;
            return crate::cli_destruction::dispatch(&store, command);
        }
        Command::PasskeyStatus { state, credential } => {
            crate::cli_passkey::passkey_status(&store, &state, &credential)?
        }
        Command::PasskeyRecoveryRevoke {
            state,
            credential,
            expected_public_key,
            confirmation,
        } => crate::cli_passkey::recover_lost_passkey(
            &store,
            &state,
            &credential,
            &expected_public_key,
            &confirmation,
        )?,
        Command::PasskeyAuthenticationChallenge {
            state,
            credential,
            challenge,
        } => crate::cli_passkey::authentication_challenge(&store, &state, &credential, &challenge)?,
        Command::PasskeyAuthenticate {
            state,
            credential,
            challenge,
            assertion,
        } => crate::cli_passkey::authenticate(&store, &state, &credential, &challenge, &assertion)?,
        Command::Registration(command) => {
            crate::cli_passkey_registration_dispatch::dispatch(&store, command)?
        }
        Command::RebindChallenge {
            state,
            credential,
            challenge,
        } => crate::cli_passkey::rebind_challenge(&store, &state, &credential, &challenge)?,
        Command::Rebind {
            state,
            credential,
            challenge,
            assertion,
        } => crate::cli_passkey::rebind(&store, &state, &credential, &challenge, &assertion)?,
        Command::AuthorizationChallenge {
            state,
            credential,
            request,
            identity_assertion,
            identity_status,
            identity_trust,
            challenge,
            origin,
        } => crate::cli_authorization::challenge(
            &store,
            CredentialAuthorizationFiles::new(
                &state,
                &credential,
                &request,
                &identity_assertion,
                &identity_status,
                &identity_trust,
            ),
            &challenge,
            &origin,
        )?,
        Command::Authorize {
            state,
            credential,
            challenge,
            assertion,
            request,
            identity_assertion,
            identity_status,
            identity_trust,
            output,
        } => crate::cli_authorization::authorize(
            &store,
            CredentialAuthorizationFiles::new(
                &state,
                &credential,
                &request,
                &identity_assertion,
                &identity_status,
                &identity_trust,
            ),
            &challenge,
            &assertion,
            &output,
        )?,
        Command::State { .. } => unreachable!("state commands are dispatched before this match"),
    };
    Ok(value)
}

fn require_bootstrap_available(command: &Command) -> Result<(), PaKeyError> {
    if bootstrap_blocked(command) {
        Err(PaKeyError::BootstrapUnavailable)
    } else {
        Ok(())
    }
}

fn dispatch_state(
    store: &PlatformCustodyStore,
    operation: &str,
    state: &std::path::Path,
) -> Result<Value, PaKeyError> {
    match operation {
        "doctor" => encoded(diagnose(store, state)),
        "initialize" => {
            require_available(store)?;
            encoded(initialize(store, state, "windows-dpapi-user")?)
        }
        "status" => {
            require_available(store)?;
            encoded(status(store, state)?)
        }
        _ => Err(PaKeyError::Usage),
    }
}

fn encoded(value: impl serde::Serialize) -> Result<Value, PaKeyError> {
    serde_json::to_value(value).map_err(|_| PaKeyError::Encoding)
}

pub(crate) fn require_available(store: &PlatformCustodyStore) -> Result<(), PaKeyError> {
    store.availability().map_err(|error| match error {
        CustodyAvailabilityError::Unavailable => PaKeyError::CustodyUnavailable,
        CustodyAvailabilityError::Denied => PaKeyError::CustodyDenied,
    })
}

pub(crate) fn pa_binding(public_key: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(public_key.as_bytes()))
    )
}
