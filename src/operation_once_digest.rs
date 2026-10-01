use crowsi_windows_operation_contracts::{OperationAuthorizeOnceRequestV2, OperationOnlyRequest};
use sha2::{Digest, Sha256};

use crate::{PaKeyError, Result};

const REQUEST_DOMAIN: &[u8] = b"CROWSI-PA-OPERATION-AUTHORIZE-ONCE-REQUEST-V2\0";
const REQUEST_ID_DOMAIN: &[u8] = b"CROWSI-PA-OPERATION-AUTHORIZE-ONCE-REQUEST-ID-V1\0";
const RESPONSE_DOMAIN: &[u8] = b"CROWSI-PA-OPERATION-AUTHORIZE-ONCE-RESPONSE-V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Binding {
    pub proof: String,
    pub request: String,
    pub request_id: String,
}

impl Binding {
    pub(crate) fn new(value: &OperationAuthorizeOnceRequestV2) -> Result<Self> {
        let proof = crowsi_credential_authority_contracts::target_device_proof_digest(
            &value.target_device_proof,
        )
        .map_err(|_| PaKeyError::Authorization)?;
        Ok(Self {
            proof: hex::encode(proof),
            request: canonical_digest(REQUEST_DOMAIN, value)?,
            request_id: request_id_digest(&value.sign_intent.request_id),
        })
    }

    pub(crate) fn file_name(&self) -> String {
        format!("operation-once-v2-{}.json", self.proof)
    }
}

pub(crate) fn response_wire(value: &OperationOnlyRequest) -> Result<Vec<u8>> {
    crate::operation_once_crypto::canonical_json(value)
}

pub(crate) fn response_digest(wire: &[u8]) -> String {
    bytes_digest(RESPONSE_DOMAIN, wire)
}

pub(crate) fn request_id_digest(value: &str) -> String {
    bytes_digest(REQUEST_ID_DOMAIN, value.as_bytes())
}

pub(crate) fn mapping_digest(
    value: &crate::operation_once_config::OperationCredentialMappingV1,
) -> Result<String> {
    canonical_digest(b"CROWSI-PA-OPERATION-AUTHORIZE-ONCE-MAPPING-V1\0", value)
}

fn canonical_digest(domain: &[u8], value: &impl serde::Serialize) -> Result<String> {
    let wire = crate::operation_once_crypto::canonical(domain, value)?;
    Ok(hex::encode(Sha256::digest(wire)))
}

fn bytes_digest(domain: &[u8], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    hex::encode(digest.finalize())
}
