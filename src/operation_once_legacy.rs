use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{PaKeyError, Result, operation_once_digest::Binding};

const SCHEMA: &str = "crowsi://policy-authority/consumed-operation-authorization/v1";
const DOMAIN: &[u8] = b"CROWSI-PA-OPERATION-AUTHORIZE-ONCE-TARGET-PROOF-V1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyReceipt {
    schema: String,
    evidence_digest_sha256: String,
    issued_at_epoch_s: u64,
    expires_at_epoch_s: u64,
    contains_secret_values: bool,
}

impl LegacyReceipt {
    pub(crate) fn decode(name: &str, wire: &[u8]) -> Result<Self> {
        if !valid_name(name) {
            return Err(PaKeyError::State);
        }
        let body = wire.strip_suffix(b"\n").ok_or(PaKeyError::State)?;
        let mut decoder = serde_json::Deserializer::from_slice(body);
        let value: Self =
            serde::Deserialize::deserialize(&mut decoder).map_err(|_| PaKeyError::State)?;
        decoder.end().map_err(|_| PaKeyError::State)?;
        let exact = value.schema == SCHEMA
            && value.evidence_digest_sha256 == format!("sha256:{name}")
            && value.issued_at_epoch_s < value.expires_at_epoch_s
            && !value.contains_secret_values
            && encode(&value)? == wire;
        exact.then_some(value).ok_or(PaKeyError::State)
    }

    pub(crate) fn retain_until(&self) -> Result<u64> {
        self.expires_at_epoch_s
            .checked_add(crate::operation_once_record::RETENTION_SECONDS)
            .ok_or(PaKeyError::State)
    }
}

pub(crate) fn file_name(binding: &Binding) -> Result<String> {
    let proof = hex::decode(&binding.proof).map_err(|_| PaKeyError::State)?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(proof);
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn valid_name(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode(value: &LegacyReceipt) -> Result<Vec<u8>> {
    let mut wire = serde_json::to_vec(value).map_err(|_| PaKeyError::State)?;
    wire.push(b'\n');
    Ok(wire)
}

#[cfg(test)]
pub(crate) fn test_wire(binding: &Binding, issued: u64, expires: u64) -> Vec<u8> {
    encode(&LegacyReceipt {
        schema: SCHEMA.into(),
        evidence_digest_sha256: format!("sha256:{}", file_name(binding).expect("name")),
        issued_at_epoch_s: issued,
        expires_at_epoch_s: expires,
        contains_secret_values: false,
    })
    .expect("legacy wire")
}
