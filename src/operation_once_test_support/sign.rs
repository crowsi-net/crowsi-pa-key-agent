use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityResult, ResponseOutcome,
    canonical_assertion_payload, canonical_current_status_payload, canonical_fresh_uv,
    canonical_response, command_digest,
};

pub(super) fn response(value: &mut SignedAuthorityExchangeV1, key: &SigningKey) {
    value.response.signature = hex::encode(
        key.sign(&canonical_response(&value.response).expect("response payload"))
            .to_bytes(),
    );
}

pub(super) fn identity(
    value: &mut SignedAuthorityExchangeV1,
    assertion_key: &SigningKey,
    status_key: &SigningKey,
) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.signature = hex::encode(
        assertion_key
            .sign(&canonical_assertion_payload(&identity.assertion))
            .to_bytes(),
    );
    identity.current_status.signature = hex::encode(
        status_key
            .sign(&canonical_current_status_payload(&identity.current_status))
            .to_bytes(),
    );
}

pub(super) fn fresh(value: &mut SignedAuthorityExchangeV1, key: &SigningKey) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvFinished { document },
    } = &mut value.response.outcome
    else {
        unreachable!()
    };
    document.signature = hex::encode(
        key.sign(&canonical_fresh_uv(document).expect("fresh payload"))
            .to_bytes(),
    );
}

pub(super) fn bind_identity_request(value: &mut SignedAuthorityExchangeV1) {
    let ResponseOutcome::Committed {
        result: AuthorityResult::IdentityEvidence(identity),
    } = &value.response.outcome
    else {
        unreachable!()
    };
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &mut value.request.command
    else {
        unreachable!()
    };
    command
        .service_id
        .clone_from(&identity.assertion.service_id);
    command
        .pairwise_subject
        .clone_from(&identity.assertion.pairwise_subject);
    command.device_id.clone_from(&identity.assertion.device_id);
    command.audience.clone_from(&identity.assertion.audience);
    command.identity_nonce.clone_from(&identity.assertion.nonce);
    let digest = command_digest(&value.request).expect("command digest");
    let [AuthorityEvidence::Signed(sender)] = value.request.evidence.as_mut_slice() else {
        unreachable!()
    };
    sender.binding_sha256.clone_from(&digest);
    value.response.command_digest = digest;
}
