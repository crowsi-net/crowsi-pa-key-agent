use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityEvidence,
    AuthorityRequestV1, AuthorityResponseV1, AuthorityResult, ResponseOutcome, command_digest,
};

pub(super) fn exchange(
    request_id: &str,
    command: AuthorityCommand,
    evidence: Vec<AuthorityEvidence>,
    result: AuthorityResult,
    issued: u64,
    generation: u64,
    authority: &SigningKey,
) -> SignedAuthorityExchangeV1 {
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request_id.into(),
        command,
        evidence,
    };
    let digest = command_digest(&request).expect("command digest");
    for item in &mut request.evidence {
        if let AuthorityEvidence::Signed(value) = item {
            value.binding_sha256.clone_from(&digest);
        }
    }
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request_id.into(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: generation,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: issued + 30,
        outcome: ResponseOutcome::Committed { result },
        key_id: "authority-key-1".into(),
        signature: String::new(),
    };
    if let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &mut response.outcome
    {
        options
            .command_binding_sha256
            .clone_from(&response.command_digest);
    }
    let mut exchange = SignedAuthorityExchangeV1 { request, response };
    super::sign::response(&mut exchange, authority);
    exchange
}
