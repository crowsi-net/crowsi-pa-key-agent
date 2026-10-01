use serde::{Deserialize, Serialize};

use crate::{PaKeyError, PaKeyStateV1, Result};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedPin {
    pub pa_key_id: String,
    pub pa_public_key_hex: String,
    pub pa_credential_revision: String,
    pub mapping_digest_sha256: String,
}

impl PreparedPin {
    pub(crate) fn new(
        state: &PaKeyStateV1,
        mapping: &crate::operation_once_config::OperationCredentialMappingV1,
    ) -> Result<Self> {
        Ok(Self {
            pa_key_id: state.key_id.clone(),
            pa_public_key_hex: state.public_key_hex.clone(),
            pa_credential_revision: state.credential_revision.clone(),
            mapping_digest_sha256: crate::operation_once_digest::mapping_digest(mapping)?,
        })
    }

    pub(crate) fn matches_mapping(
        &self,
        mapping: &crate::operation_once_config::OperationCredentialMappingV1,
    ) -> Result<()> {
        let exact =
            self.mapping_digest_sha256 == crate::operation_once_digest::mapping_digest(mapping)?;
        exact.then_some(()).ok_or(PaKeyError::State)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let exact = self.pa_key_id == "pa-credential-authorization-1"
            && lower_hex(&self.pa_public_key_hex, 64)
            && lower_hex(&self.pa_credential_revision, 32)
            && lower_hex(&self.mapping_digest_sha256, 64);
        exact.then_some(()).ok_or(PaKeyError::State)
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
