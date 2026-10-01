use crowsi_credential_broker::PlatformCustodyStore;
use crowsi_pa_key_agent::{
    PaKeyError, create_destruction_challenge, destroy_trust_domain,
    destroy_trust_domain_authorized, preflight_trust_domain_destruction,
};
use serde_json::Value;

use crate::cli_destruction_parse::DestructionCommand;

pub fn dispatch(
    store: &PlatformCustodyStore,
    command: DestructionCommand,
) -> Result<Value, PaKeyError> {
    let value = match command {
        DestructionCommand::Native {
            state,
            credential,
            confirmation,
        } => serde_json::to_value(destroy_trust_domain(
            store,
            &state,
            &credential,
            &confirmation,
        )?),
        DestructionCommand::Preflight {
            state,
            credential,
            intent,
        } => serde_json::to_value(preflight_trust_domain_destruction(
            store,
            &state,
            &credential,
            &intent,
        )?),
        DestructionCommand::Challenge {
            state,
            credential,
            intent,
            challenge,
        } => serde_json::to_value(create_destruction_challenge(
            store,
            &state,
            &credential,
            &intent,
            &challenge,
        )?),
        DestructionCommand::Finish {
            state,
            credential,
            intent,
            challenge,
            assertion,
        } => serde_json::to_value(destroy_trust_domain_authorized(
            store,
            &state,
            &credential,
            &intent,
            &challenge,
            &assertion,
        )?),
    };
    value.map_err(|_| PaKeyError::Encoding)
}
