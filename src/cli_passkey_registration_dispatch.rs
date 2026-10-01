use crowsi_credential_broker::PlatformCustodyStore;
use crowsi_pa_key_agent::PaKeyError;
use serde_json::Value;

use crate::{
    cli_parse::{Command, RegistrationCommand},
    cli_passkey_registration,
};

pub(crate) fn bootstrap_blocked(command: &Command) -> bool {
    !cfg!(feature = "owner-local-bootstrap") && matches!(command, Command::Registration(_))
}

pub fn dispatch(
    store: &PlatformCustodyStore,
    command: RegistrationCommand,
) -> Result<Value, PaKeyError> {
    match command {
        RegistrationCommand::Challenge {
            state,
            challenge,
            rp_id,
            origin,
        } => cli_passkey_registration::challenge(store, &state, &challenge, &rp_id, &origin),
        RegistrationCommand::Stage {
            state,
            challenge,
            response,
            candidate,
            proof_challenge,
            credential,
        } => cli_passkey_registration::stage(
            store,
            &state,
            &challenge,
            &response,
            &candidate,
            &proof_challenge,
            &credential,
        ),
        RegistrationCommand::Confirm {
            state,
            candidate,
            proof_challenge,
            assertion,
            credential,
        } => cli_passkey_registration::confirm(
            store,
            &state,
            &candidate,
            &proof_challenge,
            &assertion,
            &credential,
        ),
    }
}
