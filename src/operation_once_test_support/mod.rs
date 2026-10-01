pub(super) mod config;
pub(super) mod evidence;
pub(super) mod exchange;
mod exchange_base;
pub(super) mod sign;
pub(super) mod target;

use crowsi_windows_operation_contracts::{
    OperationAuthorizeOnceRequestV2, OperationOnlyCredentialClass, OperationOnlySignIntentV1,
    SigningAlgorithm,
};
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::{
    AuthorityResult, FreshUvV1, IdentityEvidenceMetadata, ResponseOutcome,
};

use crate::operation_once_config::VerifiedOperationConfig;

pub(super) struct Fixture {
    pub request: OperationAuthorizeOnceRequestV2,
    pub config: VerifiedOperationConfig,
    pub pa: SigningKey,
    pub keys: evidence::Keys,
    pub now: u64,
}

impl Fixture {
    pub fn new() -> Self {
        let keys = evidence::Keys::new();
        let selected = evidence::selected(&keys);
        let current = evidence::current(&keys);
        let mut prepared = target::prepared();
        prepared.operation_id =
            crowsi_credential_authority_contracts::endpoint_operation_id(&prepared)
                .expect("operation id");
        let operation_digest =
            crowsi_credential_authority_contracts::endpoint_operation_digest(&prepared)
                .expect("operation digest");
        let fresh = evidence::fresh(&keys, &selected, &prepared, &operation_digest);
        let management = target::management(&prepared.operation_id);
        let target_proof = target::proof(&current, &prepared, &operation_digest);
        let digest =
            crowsi_credential_authority_contracts::target_device_proof_digest(&target_proof)
                .expect("proof digest");
        let request = OperationAuthorizeOnceRequestV2 {
            schema: crowsi_windows_operation_contracts::OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA
                .into(),
            selected_identity_exchange: exchange::identity(
                &selected,
                "selected-identity",
                7,
                &keys.authority,
            ),
            selected_begin_exchange: exchange::begin(&selected, &prepared, &keys.authority),
            finish_exchange: exchange::finish(&fresh, &management.command, &keys.authority),
            current_identity_exchange: exchange::identity(
                &current,
                "current-identity",
                8,
                &keys.authority,
            ),
            prepared: prepared.clone(),
            management_request: management,
            target_device_proof: target_proof,
            sign_intent: OperationOnlySignIntentV1 {
                request_id: "custody-request-1".into(),
                credential_id: "custody-device-key-b".into(),
                expected_revision: target::revision(),
                credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
                algorithm: SigningAlgorithm::Ed25519,
                digest_sha256: format!("sha256:{}", hex::encode(digest)),
            },
        };
        Self {
            config: config::verified(&keys),
            request,
            pa: SigningKey::from_bytes(&[9; 32]),
            keys,
            now: 120,
        }
    }

    pub fn resign_fresh(&mut self) {
        sign::fresh(&mut self.request.finish_exchange, &self.keys.fresh);
        sign::response(&mut self.request.finish_exchange, &self.keys.authority);
    }

    pub fn current(&self) -> &IdentityEvidenceMetadata {
        let ResponseOutcome::Committed {
            result: AuthorityResult::IdentityEvidence(value),
        } = &self.request.current_identity_exchange.response.outcome
        else {
            unreachable!()
        };
        value
    }

    pub fn current_mut(&mut self) -> &mut IdentityEvidenceMetadata {
        let ResponseOutcome::Committed {
            result: AuthorityResult::IdentityEvidence(value),
        } = &mut self.request.current_identity_exchange.response.outcome
        else {
            unreachable!()
        };
        value
    }

    pub fn fresh(&self) -> &FreshUvV1 {
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvFinished { document },
        } = &self.request.finish_exchange.response.outcome
        else {
            unreachable!()
        };
        document
    }

    pub fn fresh_mut(&mut self) -> &mut FreshUvV1 {
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvFinished { document },
        } = &mut self.request.finish_exchange.response.outcome
        else {
            unreachable!()
        };
        document
    }

    pub fn resign_current(&mut self) {
        sign::bind_identity_request(&mut self.request.current_identity_exchange);
        sign::identity(
            &mut self.request.current_identity_exchange,
            &self.keys.identity,
            &self.keys.status,
        );
        sign::response(
            &mut self.request.current_identity_exchange,
            &self.keys.authority,
        );
    }

    pub fn rebind_sign_digest(&mut self) {
        let digest = crowsi_credential_authority_contracts::target_device_proof_digest(
            &self.request.target_device_proof,
        )
        .expect("proof digest");
        self.request.sign_intent.digest_sha256 = format!("sha256:{}", hex::encode(digest));
    }
}
