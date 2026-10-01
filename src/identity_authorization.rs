use std::path::Path;

use ihat_identity_assertion_contracts::{
    CurrentDeviceStatusV1, DeviceIdentityAssertionV1, canonical_assertion_payload,
    canonical_current_status_payload, current_status_matches_assertion, decode_assertion_strict,
    decode_current_status_strict, verify_assertion_at, verify_current_status_at,
};

use crate::{PaKeyError, Result, identity_trust, private_json, webauthn_challenge::now};

pub(crate) struct VerifiedIdentity {
    assertion: DeviceIdentityAssertionV1,
    status: CurrentDeviceStatusV1,
}

impl VerifiedIdentity {
    pub(crate) const fn assertion(&self) -> &DeviceIdentityAssertionV1 {
        &self.assertion
    }

    pub(crate) const fn status(&self) -> &CurrentDeviceStatusV1 {
        &self.status
    }
}

pub(crate) fn verify(
    assertion_path: &Path,
    status_path: &Path,
    trust_path: &Path,
) -> Result<VerifiedIdentity> {
    let trust = identity_trust::read(trust_path)?;
    let assertion = decode_assertion_strict(&private_json::read_owner_bytes(assertion_path)?)
        .map_err(|_| PaKeyError::Authorization)?;
    let status = decode_current_status_strict(&private_json::read_owner_bytes(status_path)?)
        .map_err(|_| PaKeyError::Authorization)?;
    let timestamp = u64::try_from(now()).map_err(|_| PaKeyError::Authorization)?;
    verify_assertion_at(
        &assertion,
        &trust.assertion,
        &trust.issuer,
        &trust.audience,
        timestamp,
    )
    .map_err(|_| PaKeyError::Authorization)?;
    verify_current_status_at(
        &status,
        &trust.status,
        &trust.issuer,
        &trust.audience,
        timestamp,
    )
    .map_err(|_| PaKeyError::Authorization)?;
    if assertion.service_id != trust.service_id
        || status.service_id != trust.service_id
        || !current_status_matches_assertion(&status, &assertion)
    {
        return Err(PaKeyError::Authorization);
    }
    Ok(VerifiedIdentity { assertion, status })
}

pub(crate) fn binding(value: &VerifiedIdentity) -> String {
    let assertion = canonical_assertion_payload(&value.assertion);
    let status = canonical_current_status_payload(&value.status);
    let mut canonical = b"CROWSI-PA-IDENTITY-CONTEXT-V2\n".to_vec();
    record(&mut canonical, &assertion);
    record(&mut canonical, &status);
    crowsi_local_control_bridge::sha256_digest(&canonical)
}

fn record(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}
