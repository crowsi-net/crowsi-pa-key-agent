use std::path::Path;

use crowsi_credential_broker::CredentialStore;
use crowsi_windows_operation_contracts::{
    OperationAuthorizeOnceRequestV2, OperationOnlyRequest, decode_operation_authorize_once_request,
};
use ed25519_dalek::SigningKey;

use crate::{PaKeyError, PaKeyStateV1, Result, operation_once_config::VerifiedOperationConfig};

#[cfg(test)]
pub(crate) fn authorize<S: CredentialStore>(
    store: &S,
    config: &VerifiedOperationConfig,
    state_wire: &[u8],
    request_wire: &[u8],
    now: u64,
) -> Result<OperationOnlyRequest> {
    let wire = authorize_wire_checked(store, config, state_wire, request_wire, now, |_| Ok(()))?;
    crowsi_windows_operation_contracts::decode_operation_request(&wire)
        .map_err(|_| PaKeyError::State)
}

pub(crate) fn authorize_wire_checked<S: CredentialStore>(
    store: &S,
    config: &VerifiedOperationConfig,
    state_wire: &[u8],
    request_wire: &[u8],
    now: u64,
    custody_check: impl FnOnce(&S) -> Result<()>,
) -> Result<Vec<u8>> {
    let request = decode(request_wire)?;
    let mut transaction = crate::operation_once_ledger::Transaction::open(
        Path::new(&config.0.replay_directory),
        &request,
        now,
    )?;
    if let Some(response) = transaction.response()? {
        return Ok(response);
    }
    custody_check(store)?;
    let mapping = pinned_mapping(&request);
    let (pin, issued, entry) = if let Some(pin) = transaction.prepared_pin() {
        pin.matches_mapping(&mapping)?;
        let entry = pinned_entry(store, &pin)?;
        (
            pin,
            transaction.issued_at().ok_or(PaKeyError::State)?,
            entry,
        )
    } else {
        fresh_entry(store, config, state_wire, &request, &mut transaction, now)?
    };
    let output = entry
        .into_secret()
        .expose(|secret| build_with_secret(secret, &pin, &request, &mapping, issued))?;
    let response = crate::operation_once_digest::response_wire(&output)?;
    transaction.complete(&response)?;
    Ok(response)
}

pub(crate) fn recover_wire(
    config: &VerifiedOperationConfig,
    request_wire: &[u8],
    now: u64,
) -> Result<Option<Vec<u8>>> {
    let request = decode(request_wire)?;
    crate::operation_once_ledger::recover(Path::new(&config.0.replay_directory), &request, now)
}

fn decode(wire: &[u8]) -> Result<OperationAuthorizeOnceRequestV2> {
    decode_operation_authorize_once_request(wire).map_err(|_| PaKeyError::Authorization)
}

fn state(wire: &[u8]) -> Result<PaKeyStateV1> {
    if wire.is_empty() || wire.len() > 65_536 {
        return Err(PaKeyError::State);
    }
    let mut decoder = serde_json::Deserializer::from_slice(wire);
    let value = serde::Deserialize::deserialize(&mut decoder).map_err(|_| PaKeyError::State)?;
    decoder.end().map_err(|_| PaKeyError::State)?;
    if !PaKeyStateV1::valid(&value) || value.key_id != "pa-credential-authorization-1" {
        return Err(PaKeyError::State);
    }
    Ok(value)
}

fn build_with_secret(
    bytes: &[u8],
    pin: &crate::operation_once_pin::PreparedPin,
    request: &OperationAuthorizeOnceRequestV2,
    mapping: &crate::operation_once_config::OperationCredentialMappingV1,
    issued: u64,
) -> Result<OperationOnlyRequest> {
    let seed: [u8; 32] = bytes.try_into().map_err(|_| PaKeyError::State)?;
    let key = SigningKey::from_bytes(&seed);
    if hex::encode(key.verifying_key().to_bytes()) != pin.pa_public_key_hex {
        return Err(PaKeyError::State);
    }
    crate::operation_once_document::build(request, mapping, &pin.pa_key_id, &key, issued)
}

fn pinned_mapping(
    request: &OperationAuthorizeOnceRequestV2,
) -> crate::operation_once_config::OperationCredentialMappingV1 {
    let proof = &request.target_device_proof;
    crate::operation_once_config::OperationCredentialMappingV1 {
        opaque_owner_ref: proof.owner_ref.clone(),
        service_id: proof.service_id.clone(),
        device_id: proof.target_device_ref.clone(),
        device_proof_key_ref: proof.device_proof_key_ref.clone(),
        custody_credential_id: request.sign_intent.credential_id.clone(),
        expected_revision: request.sign_intent.expected_revision.clone(),
        credential_class: request.sign_intent.credential_class,
    }
}

include!("operation_once_runtime_authority.rs");
include!("operation_once_runtime_independent.rs");
