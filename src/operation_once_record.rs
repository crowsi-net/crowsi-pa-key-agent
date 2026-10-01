use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use crowsi_windows_operation_contracts::{OperationOnlyAction, decode_operation_request};
use serde::{Deserialize, Serialize};

use crate::{PaKeyError, Result, operation_once_digest::Binding};

pub(crate) const SCHEMA: &str = "crowsi://policy-authority/operation-once-receipt/v2";
pub(crate) const MAX_RECORD_BYTES: u64 = 32_768;
pub(crate) const RETENTION_SECONDS: u64 = 600;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Phase {
    Prepared,
    Completed,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub schema: String,
    pub proof_digest_sha256: String,
    pub request_digest_sha256: String,
    pub request_id_digest_sha256: String,
    pub issued_at_epoch_s: u64,
    pub proof_expires_at_epoch_s: u64,
    pub retain_until_epoch_s: u64,
    pub prepared_pin: crate::operation_once_pin::PreparedPin,
    pub phase: Phase,
    pub response_digest_sha256: Option<String>,
    pub response_wire_base64: Option<String>,
    pub contains_secret_values: bool,
}

impl Record {
    pub(crate) fn prepared(
        binding: &Binding,
        issued: u64,
        expires: u64,
        prepared_pin: crate::operation_once_pin::PreparedPin,
    ) -> Result<Self> {
        let retain = expires
            .checked_add(RETENTION_SECONDS)
            .ok_or(PaKeyError::Authorization)?;
        Ok(Self {
            schema: SCHEMA.into(),
            proof_digest_sha256: binding.proof.clone(),
            request_digest_sha256: binding.request.clone(),
            request_id_digest_sha256: binding.request_id.clone(),
            issued_at_epoch_s: issued,
            proof_expires_at_epoch_s: expires,
            retain_until_epoch_s: retain,
            prepared_pin,
            phase: Phase::Prepared,
            response_digest_sha256: None,
            response_wire_base64: None,
            contains_secret_values: false,
        })
    }
    pub(crate) fn complete(&self, wire: &[u8]) -> Result<Self> {
        let mut value = self.clone();
        value.phase = Phase::Completed;
        value.response_digest_sha256 = Some(crate::operation_once_digest::response_digest(wire));
        value.response_wire_base64 = Some(STANDARD_NO_PAD.encode(wire));
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn response(&self) -> Result<Option<Vec<u8>>> {
        match (&self.phase, &self.response_wire_base64) {
            (Phase::Prepared, None) => Ok(None),
            (Phase::Completed, Some(value)) => STANDARD_NO_PAD
                .decode(value)
                .map(Some)
                .map_err(|_| PaKeyError::State),
            _ => Err(PaKeyError::State),
        }
    }

    pub(crate) fn binding_matches(&self, binding: &Binding) -> bool {
        self.proof_digest_sha256 == binding.proof
            && self.request_digest_sha256 == binding.request
            && self.request_id_digest_sha256 == binding.request_id
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let base = self.schema == SCHEMA
            && digest(&self.proof_digest_sha256)
            && digest(&self.request_digest_sha256)
            && digest(&self.request_id_digest_sha256)
            && self.issued_at_epoch_s < self.proof_expires_at_epoch_s
            && self.retain_until_epoch_s
                == self
                    .proof_expires_at_epoch_s
                    .saturating_add(RETENTION_SECONDS)
            && self.prepared_pin.validate().is_ok()
            && !self.contains_secret_values;
        if !base {
            return Err(PaKeyError::State);
        }
        let Some(wire) = self.response()? else {
            return (self.response_digest_sha256.is_none() && self.phase == Phase::Prepared)
                .then_some(())
                .ok_or(PaKeyError::State);
        };
        validate_response(self, &wire)
    }
}

fn validate_response(record: &Record, wire: &[u8]) -> Result<()> {
    let value = decode_operation_request(wire).map_err(|_| PaKeyError::State)?;
    let canonical =
        crate::operation_once_digest::response_wire(&value).map_err(|_| PaKeyError::State)?;
    let OperationOnlyAction::Sign {
        digest_sha256: proof,
        ..
    } = &value.action
    else {
        return Err(PaKeyError::State);
    };
    let signed =
        crowsi_windows_operation_contracts::authorization_signing_bytes(&value.pa_authorization)
            .map_err(|_| PaKeyError::State)?;
    crate::operation_once_crypto::verify_signature(
        &record.prepared_pin.pa_public_key_hex,
        &value.pa_authorization.signature_hex,
        &signed,
    )
    .map_err(|_| PaKeyError::State)?;
    let response_digest = crate::operation_once_digest::response_digest(wire);
    let request_digest = crowsi_windows_operation_contracts::operation_request_digest(&value)
        .map_err(|_| PaKeyError::State)?;
    let valid = canonical == wire
        && proof == &format!("sha256:{}", record.proof_digest_sha256)
        && crate::operation_once_digest::request_id_digest(&value.request_id)
            == record.request_id_digest_sha256
        && value.pa_authorization.binding.request_digest_sha256 == request_digest
        && value.pa_authorization.issued_at_epoch_s == record.issued_at_epoch_s
        && value.pa_authorization.key_id == record.prepared_pin.pa_key_id
        && value.pa_authorization.expires_at_epoch_s <= record.proof_expires_at_epoch_s
        && record.response_digest_sha256.as_deref() == Some(response_digest.as_str());
    valid.then_some(()).ok_or(PaKeyError::State)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
